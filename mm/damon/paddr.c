// SPDX-License-Identifier: GPL-2.0
/*
 * DAMON Primitives for The Physical Address Space
 *
 * Author: SeongJae Park <sj@kernel.org>
 */

#define pr_fmt(fmt) "damon-pa: " fmt

#include <linux/mmu_notifier.h>
#include <linux/page_idle.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/memory-tiers.h>
#include <linux/migrate.h>
#include <linux/mm_inline.h>

#include "../internal.h"
#include "ops-common.h"

static void damon_pa_mkold(unsigned long paddr)
{
	struct folio *folio = damon_get_folio(PHYS_PFN(paddr));

	if (!folio)
		return;

	damon_folio_mkold(folio);
	folio_put(folio);
}

static void __damon_pa_prepare_access_check(struct damon_region *r)
{
	r->sampling_addr = damon_rand(r->ar.start, r->ar.end);

	damon_pa_mkold(r->sampling_addr);
}

static void damon_pa_prepare_access_checks(struct damon_ctx *ctx)
{
	struct damon_target *t;
	struct damon_region *r;

	damon_for_each_target(t, ctx) {
		damon_for_each_region(r, t)
			__damon_pa_prepare_access_check(r);
	}
}

static bool damon_pa_young(unsigned long paddr, unsigned long *folio_sz)
{
	struct folio *folio = damon_get_folio(PHYS_PFN(paddr));
	bool accessed;

	if (!folio)
		return false;

	accessed = damon_folio_young(folio);
	*folio_sz = folio_size(folio);
	folio_put(folio);
	return accessed;
}

static void __damon_pa_check_access(struct damon_region *r,
		struct damon_attrs *attrs)
{
	static unsigned long last_addr;
	static unsigned long last_folio_sz = PAGE_SIZE;
	static bool last_accessed;

	/* If the region is in the last checked page, reuse the result */
	if (ALIGN_DOWN(last_addr, last_folio_sz) ==
				ALIGN_DOWN(r->sampling_addr, last_folio_sz)) {
		damon_update_region_access_rate(r, last_accessed, attrs);
		return;
	}

	last_accessed = damon_pa_young(r->sampling_addr, &last_folio_sz);
	damon_update_region_access_rate(r, last_accessed, attrs);

	last_addr = r->sampling_addr;
}

static unsigned int damon_pa_check_accesses(struct damon_ctx *ctx)
{
	struct damon_target *t;
	struct damon_region *r;
	unsigned int max_nr_accesses = 0;

	damon_for_each_target(t, ctx) {
		damon_for_each_region(r, t) {
			__damon_pa_check_access(r, &ctx->attrs);
			max_nr_accesses = max(r->nr_accesses, max_nr_accesses);
		}
	}

	return max_nr_accesses;
}

static unsigned long damon_pa_pageout(struct damon_region *r, struct damos *s)
{
	unsigned long addr, applied;
	LIST_HEAD(folio_list);
	bool install_young_filter = true;
	struct damos_filter *filter;

	/* check access in page level again by default */
	damos_for_each_filter(filter, s) {
		if (filter->type == DAMOS_FILTER_TYPE_YOUNG) {
			install_young_filter = false;
			break;
		}
	}
	if (install_young_filter) {
		filter = damos_new_filter(DAMOS_FILTER_TYPE_YOUNG, true);
		if (!filter)
			return 0;
		damos_add_filter(s, filter);
	}

	addr = r->ar.start;
	while (addr < r->ar.end) {
		struct folio *folio = damon_get_folio(PHYS_PFN(addr));

		if (!folio) {
			addr += PAGE_SIZE;
			continue;
		}

		if (damos_filter_out_folio(s, folio))
			goto put_folio;

		folio_clear_referenced(folio);
		folio_test_clear_young(folio);
		if (!folio_isolate_lru(folio))
			goto put_folio;
		if (folio_test_unevictable(folio))
			folio_putback_lru(folio);
		else
			list_add(&folio->lru, &folio_list);
put_folio:
		addr += folio_size(folio);
		folio_put(folio);
	}
	if (install_young_filter)
		damos_destroy_filter(filter);
	applied = reclaim_pages(&folio_list);
	cond_resched();
	return applied * PAGE_SIZE;
}

static inline unsigned long damon_pa_mark_accessed_or_deactivate(
		struct damon_region *r, struct damos *s, bool mark_accessed)
{
	unsigned long addr, applied = 0;

	addr = r->ar.start;
	while (addr < r->ar.end) {
		struct folio *folio = damon_get_folio(PHYS_PFN(addr));

		if (!folio) {
			addr += PAGE_SIZE;
			continue;
		}

		if (damos_filter_out_folio(s, folio))
			goto put_folio;

		if (mark_accessed)
			folio_mark_accessed(folio);
		else
			folio_deactivate(folio);
		applied += folio_nr_pages(folio);
put_folio:
		addr += folio_size(folio);
		folio_put(folio);
	}
	return applied * PAGE_SIZE;
}

static unsigned long damon_pa_mark_accessed(struct damon_region *r,
	struct damos *s)
{
	return damon_pa_mark_accessed_or_deactivate(r, s, true);
}

static unsigned long damon_pa_deactivate_pages(struct damon_region *r,
	struct damos *s)
{
	return damon_pa_mark_accessed_or_deactivate(r, s, false);
}

static unsigned int __damon_pa_migrate_folio_list(
		struct list_head *migrate_folios, struct pglist_data *pgdat,
		int target_nid)
{
	unsigned int nr_succeeded = 0;
	nodemask_t allowed_mask = NODE_MASK_NONE;
	struct migration_target_control mtc = {
		/*
		 * Allocate from 'node', or fail quickly and quietly.
		 * When this happens, 'page' will likely just be discarded
		 * instead of migrated.
		 */
		.gfp_mask = (GFP_HIGHUSER_MOVABLE & ~__GFP_RECLAIM) |
			__GFP_NOWARN | __GFP_NOMEMALLOC | GFP_NOWAIT,
		.nid = target_nid,
		.nmask = &allowed_mask
	};

	if (pgdat->node_id == target_nid || target_nid == NUMA_NO_NODE)
		return 0;

	if (list_empty(migrate_folios))
		return 0;

	/* Migration ignores all cpuset and mempolicy settings */
	migrate_pages(migrate_folios, alloc_migrate_folio, NULL,
		      (unsigned long)&mtc, MIGRATE_ASYNC, MR_DAMON,
		      &nr_succeeded);

	return nr_succeeded;
}

static unsigned int damon_pa_migrate_folio_list(struct list_head *folio_list,
						struct pglist_data *pgdat,
						int target_nid)
{
	unsigned int nr_migrated = 0;
	struct folio *folio;
	LIST_HEAD(ret_folios);
	LIST_HEAD(migrate_folios);

	while (!list_empty(folio_list)) {
		struct folio *folio;

		cond_resched();

		folio = lru_to_folio(folio_list);
		list_del(&folio->lru);

		if (!folio_trylock(folio))
			goto keep;

		/* Relocate its contents to another node. */
		list_add(&folio->lru, &migrate_folios);
		folio_unlock(folio);
		continue;
keep:
		list_add(&folio->lru, &ret_folios);
	}
	/* 'folio_list' is always empty here */

	/* Migrate folios selected for migration */
	nr_migrated += __damon_pa_migrate_folio_list(
			&migrate_folios, pgdat, target_nid);
	/*
	 * Folios that could not be migrated are still in @migrate_folios.  Add
	 * those back on @folio_list
	 */
	if (!list_empty(&migrate_folios))
		list_splice_init(&migrate_folios, folio_list);

	try_to_unmap_flush();

	list_splice(&ret_folios, folio_list);

	while (!list_empty(folio_list)) {
		folio = lru_to_folio(folio_list);
		list_del(&folio->lru);
		folio_putback_lru(folio);
	}

	return nr_migrated;
}

unsigned long damon_migrate_pages(struct list_head *folio_list,
					    int target_nid)
{
	int nid;
	unsigned long nr_migrated = 0;
	LIST_HEAD(node_folio_list);
	unsigned int noreclaim_flag;

	if (list_empty(folio_list))
		return nr_migrated;

	noreclaim_flag = memalloc_noreclaim_save();

	nid = folio_nid(lru_to_folio(folio_list));
	do {
		struct folio *folio = lru_to_folio(folio_list);

		if (nid == folio_nid(folio)) {
			list_move(&folio->lru, &node_folio_list);
			continue;
		}

		nr_migrated += damon_pa_migrate_folio_list(&node_folio_list,
							   NODE_DATA(nid),
							   target_nid);
		nid = folio_nid(lru_to_folio(folio_list));
	} while (!list_empty(folio_list));

	nr_migrated += damon_pa_migrate_folio_list(&node_folio_list,
						   NODE_DATA(nid),
						   target_nid);

	memalloc_noreclaim_restore(noreclaim_flag);

	return nr_migrated;
}

static unsigned long damon_pa_migrate(struct damon_region *r, struct damos *s)
{
	unsigned long addr, applied;
	LIST_HEAD(folio_list);

	addr = r->ar.start;
	while (addr < r->ar.end) {
		struct folio *folio = damon_get_folio(PHYS_PFN(addr));

		if (!folio) {
			addr += PAGE_SIZE;
			continue;
		}

		if (damos_filter_out_folio(s, folio))
			goto put_folio;

		if (!folio_isolate_lru(folio))
			goto put_folio;
		list_add(&folio->lru, &folio_list);
put_folio:
		addr += folio_size(folio);
		folio_put(folio);
	}
	applied = damon_migrate_pages(&folio_list, s->target_nid);
	cond_resched();
	return applied * PAGE_SIZE;
}

static bool damon_pa_interleave_rmap(struct folio *folio, struct vm_area_struct *vma,
        unsigned long addr, void *arg)
{
	struct mempolicy *pol;
	struct task_struct *task;
	pgoff_t ilx;
	int target_nid;
	struct damos_interleave_private *priv = arg;

	task = vma->vm_mm->owner;
	if (!task)
		return true;

	pol = get_task_policy(task);
	// If the vma policy isn't correct, exit, but try other vmas the folio
	// is mapped to
	if (!pol)
		return true;
	if (pol->mode != MPOL_WEIGHTED_INTERLEAVE) {
		mpol_cond_put(pol);
		return true;
	}

	ilx = vma->vm_pgoff >> folio_order(folio);
	ilx += (addr - vma->vm_start) >> (PAGE_SHIFT + folio_order(folio));

	policy_nodemask(0, pol, ilx, &target_nid);

	// Only move the pages if they are in the opposite node
	if (target_nid == 0 && folio_nid(folio) != 0)
		list_add(&folio->lru, &priv->local_folios);
	else if (target_nid == 1 && folio_nid(folio) != 1)
		list_add(&folio->lru, &priv->remote_folios);
	else
		folio_putback_lru(folio);

	mpol_cond_put(pol);

	// Don't try other vmas
	return false;
}

static unsigned long damon_pa_interleave(struct damon_region *r, struct damos *s) {
	struct damos_interleave_private priv;
	struct rmap_walk_control rwc;
	unsigned long addr;
	unsigned long applied;
	unsigned long local_count = 0;
	unsigned long remote_count = 0;

	INIT_LIST_HEAD(&priv.local_folios);
	INIT_LIST_HEAD(&priv.remote_folios);
	priv.scheme = s;

	memset(&rwc, 0, sizeof(struct rmap_walk_control));
	rwc.rmap_one = damon_pa_interleave_rmap;
	rwc.arg = &priv;

	addr = r->ar.start;
	while (addr < r->ar.end) {
		struct folio *folio = damon_get_folio(PHYS_PFN(addr));

		if (!folio) {
			addr += PAGE_SIZE;
			continue;
		}

		if (damos_filter_out_folio(s, folio))
			goto put_folio;

		if (!folio_isolate_lru(folio))
			goto put_folio;

		rmap_walk(folio, &rwc);
put_folio:
		addr += folio_size(folio);
		folio_put(folio);
	}

	local_count = damon_migrate_pages(&priv.local_folios, 0);
	remote_count = damon_migrate_pages(&priv.remote_folios, 1);

	applied = local_count + remote_count;

	return applied * PAGE_SIZE;
}

static unsigned long damon_pa_apply_scheme(struct damon_ctx *ctx,
		struct damon_target *t, struct damon_region *r,
		struct damos *scheme)
{
	switch (scheme->action) {
	case DAMOS_PAGEOUT:
		return damon_pa_pageout(r, scheme);
	case DAMOS_LRU_PRIO:
		return damon_pa_mark_accessed(r, scheme);
	case DAMOS_LRU_DEPRIO:
		return damon_pa_deactivate_pages(r, scheme);
	case DAMOS_MIGRATE_HOT:
	case DAMOS_MIGRATE_COLD:
		return damon_pa_migrate(r, scheme);
	case DAMOS_INTERLEAVE:
		return damon_pa_interleave(r, scheme);
	case DAMOS_STAT:
		break;
	default:
		/* DAMOS actions that not yet supported by 'paddr'. */
		break;
	}
	return 0;
}

static int damon_pa_scheme_score(struct damon_ctx *context,
		struct damon_target *t, struct damon_region *r,
		struct damos *scheme)
{
	switch (scheme->action) {
	case DAMOS_PAGEOUT:
		return damon_cold_score(context, r, scheme);
	case DAMOS_LRU_PRIO:
		return damon_hot_score(context, r, scheme);
	case DAMOS_LRU_DEPRIO:
		return damon_cold_score(context, r, scheme);
	case DAMOS_MIGRATE_HOT:
		return damon_hot_score(context, r, scheme);
	case DAMOS_MIGRATE_COLD:
		return damon_cold_score(context, r, scheme);
	default:
		break;
	}

	return DAMOS_MAX_SCORE;
}

static int __init damon_pa_initcall(void)
{
	struct damon_operations ops = {
		.id = DAMON_OPS_PADDR,
		.init = NULL,
		.update = NULL,
		.prepare_access_checks = damon_pa_prepare_access_checks,
		.check_accesses = damon_pa_check_accesses,
		.reset_aggregated = NULL,
		.target_valid = NULL,
		.cleanup = NULL,
		.apply_scheme = damon_pa_apply_scheme,
		.get_scheme_score = damon_pa_scheme_score,
	};

	return damon_register_ops(&ops);
};

subsys_initcall(damon_pa_initcall);

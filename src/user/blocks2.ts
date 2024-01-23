import db = require('../database');
import plugins = require('../plugins');
import cacheCreate = require('../cache/lru');

interface UserBlocks {
    _cache: any; // Add type for cache object
    is: (targetUid: number, uids: number | number[]) => Promise<boolean | boolean[]>;
    can: (callerUid: number, blockerUid: number, blockeeUid: number, type: 'block' | 'unblock') => Promise<void>;
    list: (uids: number | number[]) => Promise<number[] | number[][]>;
    add: (targetUid: number, uid: number) => Promise<void>;
    remove: (targetUid: number, uid: number) => Promise<void>;
    applyChecks: (type: 'block' | 'unblock', targetUid: number, uid: number) => Promise<void>;
    filterUids: (targetUid: number, uids: number[]) => Promise<number[]>;
    filter: (uid: number, property?: string | string[], set?: any[]) => Promise<any[]>;
}
function blockFunction(User: { 
    blocks: UserBlocks,
    isAdminOrGlobalMod: (uid: number) => Promise<boolean>,
    incrementUserFieldBy: (uid: number, field: string, value: number) => Promise<void>,
    decrementUserFieldBy: (uid: number, field: string, value: number) => Promise<void>
}) {
    User.blocks = {
        _cache: cacheCreate({
            name: 'user:blocks',
            max: 100,
            ttl: 0,
        }),
        is: async function (targetUid, uids){
            const isArray = Array.isArray(uids);
            uids = isArray ? (uids as number[]) : [uids as number];
            const blocks = await User.blocks.list(uids);
            const isBlocked: boolean[] = uids.map((uid: number, index: number) => (blocks[index] as number[]).includes(parseInt(targetUid.toString(), 10)));
            return isArray ? isBlocked : isBlocked[0];
        },
        can: async function (callerUid, blockerUid, blockeeUid, type) {
            // Guests can't block
            if (blockerUid === 0 || blockeeUid === 0) {
                throw new Error('[[error:cannot-block-guest]]');
            } else if (blockerUid === blockeeUid) {
                throw new Error('[[error:cannot-block-self]]');
            }

            // Administrators and global moderators cannot be blocked
            // Only admins/mods can block users as another user
            const [isCallerAdminOrMod, isBlockeeAdminOrMod] = await Promise.all([
                User.isAdminOrGlobalMod(callerUid),
                User.isAdminOrGlobalMod(blockeeUid),
            ]);
            if (isBlockeeAdminOrMod && type === 'block') {
                throw new Error('[[error:cannot-block-privileged]]');
            }
            if (parseInt(callerUid.toString(), 10) !== parseInt(blockerUid.toString(), 10) && !isCallerAdminOrMod) {
                throw new Error('[[error:no-privileges]]');
            }
        },
        list: async function (uids) {
            const isArray = Array.isArray(uids);
            uids = (isArray ? (Array.isArray(uids) ? uids : [uids]) : [uids]) as number[];
            uids = uids.map(uid => parseInt(uid.toString(), 10));

            const cachedData = {};
            const unCachedUids = User.blocks._cache.getUnCachedKeys(uids, cachedData);
            if (unCachedUids.length) {
                const unCachedData = await db.getSortedSetsMembers(unCachedUids.map(uid => `uid:${uid}:blocked_uids`));
                unCachedUids.forEach((uid, index) => {
                    cachedData[uid] = (unCachedData[index] || []).map(uid => parseInt(uid, 10));
                    User.blocks._cache.set(uid, cachedData[uid]);
                });
            }
            const result = uids.map(uid => cachedData[uid] || []);
            return isArray ? result.slice() : result[0];
        },
        add: async function (targetUid, uid) {
            await User.blocks.applyChecks('block', targetUid, uid);
            await db.sortedSetAdd(`uid:${uid}:blocked_uids`, Date.now(), targetUid);
            await User.incrementUserFieldBy(uid, 'blocksCount', 1);
            User.blocks._cache.del(parseInt(uid.toString(), 10));
            plugins.hooks.fire('action:user.blocks.add', { uid: uid, targetUid: targetUid });
        },
        remove: async function (targetUid, uid) {
            await User.blocks.applyChecks('unblock', targetUid, uid);
            await db.sortedSetRemove(`uid:${uid}:blocked_uids`, targetUid);
            await User.decrementUserFieldBy(uid, 'blocksCount', 1);
            User.blocks._cache.del(parseInt(uid.toString(), 10));
            plugins.hooks.fire('action:user.blocks.remove', { uid: uid, targetUid: targetUid });
        },
        applyChecks: async function (type, targetUid, uid) {
            await User.blocks.can(uid, uid, targetUid,type);
            const isBlock = type === 'block';
            const is = await User.blocks.is(targetUid, uid);
            if (is === isBlock) {
                throw new Error(`[[error:already-${isBlock ? 'blocked' : 'unblocked'}]]`);
            }
        },
        filterUids: async function (targetUid, uids) {
            const isBlocked = await User.blocks.is(targetUid, uids);
            return uids.filter((uid, index) => !isBlocked[index]);
        },
        filter: async function (uid, property, set) {
            // Given whatever is passed in, iterates through it, and removes entries made by blocked uids
            // property is optional
            if (Array.isArray(property) && typeof set === 'undefined') {
                set = property;
                property = 'uid';
            }

            if (!Array.isArray(set) || !set.length) {
                return set;
            }

            const isPlain = typeof set[0] !== 'object';
            const blocked_uids = await User.blocks.list(uid);
            const flatBlockedUids: number[] = ([] as number[]).concat(...blocked_uids);
            const blockedSet:Set<number> = new Set(flatBlockedUids);

            set = set.filter((item: any) => !blockedSet.has(parseInt(isPlain ? item : (item && item[property as string]), 10)));
            const data = await plugins.hooks.fire('filter:user.blocks.filter', { set: set, property: property, uid: uid, blockedSet: blockedSet });

            return data.set;
        }


    };
}; export = blockFunction;

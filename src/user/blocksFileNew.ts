'use strict';

//changed
import db = require('../database');
import plugins = require('../plugins');
import cacheCreate = require('../cache/lru');
//end change
interface UserBlocksCache {
    _cache: any;
}

interface UserBlocks {
    is: (targetUid: number, uids: number[] | number) => Promise<boolean | boolean[]>;
    can: (callerUid: number, blockerUid: number, blockeeUid: number, type: string) => Promise<void>;
    list: (uids: number[] | number) => Promise<number[] | number[][]>;
    add: (targetUid: number, uid: number) => Promise<void>;
    remove: (targetUid: number, uid: number) => Promise<void>;
    applyChecks: (type: string, targetUid: number, uid: number) => Promise<void>;
    filterUids: (targetUid: number, uids: number[]) => Promise<number[]>;
    filter: (uid: number, property?: string | string[], set?: any[]) => Promise<any[]>;
}

function blockFunction(User: any) {
    User.blocks = {
        _cache: cacheCreate({
            name: 'user:blocks',
            max: 100,
            ttl: 0,
        }),
    } as UserBlocksCache;

    User.blocks.is = async function (targetUid: number, uids: number[] | number): Promise<boolean | boolean[]> {
        const isArray: boolean = Array.isArray(uids);
        uids = isArray ? uids as number[] : [uids as number];//modified to remove error
        const blocks: number[][] = await User.blocks.list(uids);
        const isBlocked: boolean[] = uids.map((uid: number, index: number) => blocks[index] && blocks[index].includes(parseInt(targetUid.toString(), 10)));
        return isArray ? isBlocked : isBlocked[0];
    };

    User.blocks.can = async function (callerUid: number, blockerUid: number, blockeeUid: number, type: string): Promise<void> {
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
    };

    User.blocks.list = async function (uids: number[] | number): Promise<number[] | number[][]> {
        const isArray: boolean = Array.isArray(uids);
        //changed
        uids = (isArray ? uids : [uids]) as number[]; // Type assertion to ensure 'uids' is treated as an array
        uids = uids.map((uid: number) => parseInt(uid.toString(), 10));

        //end change
        const cachedData: any = {};
        const unCachedUids: number[] = User.blocks._cache.getUnCachedKeys(uids, cachedData);
        if (unCachedUids.length) {
            const unCachedData: any[] = await db.getSortedSetsMembers(unCachedUids.map((uid: number) => `uid:${uid}:blocked_uids`));
            unCachedUids.forEach((uid: number, index: number) => {
                cachedData[uid] = (unCachedData[index] || []).map((uid: string) => parseInt(uid, 10));
                User.blocks._cache.set(uid, cachedData[uid]);
            });
        }
        const result: number[] | number[][] = uids.map((uid: number) => cachedData[uid] || []);
        //changed
        return isArray ? result.slice() as number[] : result[0] as number[] | number[][];
    };

    User.blocks.add = async function (targetUid: number, uid: number): Promise<void> {
        await User.blocks.applyChecks('block', targetUid, uid);
        await db.sortedSetAdd(`uid:${uid}:blocked_uids`, Date.now(), targetUid);
        await User.incrementUserFieldBy(uid, 'blocksCount', 1);
        User.blocks._cache.del(parseInt(uid.toString(), 10));
        plugins.hooks.fire('action:user.blocks.add', { uid: uid, targetUid: targetUid });
    };

    User.blocks.remove = async function (targetUid: number, uid: number): Promise<void> {
        await User.blocks.applyChecks('unblock', targetUid, uid);
        await db.sortedSetRemove(`uid:${uid}:blocked_uids`, targetUid);
        await User.decrementUserFieldBy(uid, 'blocksCount', 1);
        User.blocks._cache.del(parseInt(uid.toString(), 10));
        plugins.hooks.fire('action:user.blocks.remove', { uid: uid, targetUid: targetUid });
    };

    User.blocks.applyChecks = async function (type: string, targetUid: number, uid: number): Promise<void> {
        await User.blocks.can(uid, uid, targetUid);
        const isBlock: boolean = type === 'block';
        const is: boolean | boolean[] = await User.blocks.is(targetUid, uid);
        if (is === isBlock) {
            throw new Error(`[[error:already-${isBlock ? 'blocked' : 'unblocked'}]]`);
        }
    };

    User.blocks.filterUids = async function (targetUid: number, uids: number[]): Promise<number[]> {
        const isBlocked: boolean | boolean[] = await User.blocks.is(targetUid, uids);
        return uids.filter((uid: number, index: number) => !isBlocked[index]);
    };

    User.blocks.filter = async function (uid: number, property?: string | string[], set?: any[]): Promise<any[]> {
        // Given whatever is passed in, iterates through it, and removes entries made by blocked uids
        // property is optional
        if (Array.isArray(property) && typeof set === 'undefined') {
            set = property;
            property = 'uid';
        }

        if (!Array.isArray(set) || !set.length) {
            return set;
        }

        const isPlain: boolean = typeof set[0] !== 'object';
        const blocked_uids: number[] = await User.blocks.list(uid);
        const blockedSet: Set<number> = new Set(blocked_uids);

        //begin change
        set = set.filter((item: any) => {
            const prop = Array.isArray(property) ? property[0] : property;
            return !blockedSet.has(parseInt(isPlain ? item : (item && item[prop]), 10));
        });        

        //end change
        const data: any = await plugins.hooks.fire('filter:user.blocks.filter', { set: set, property: property, uid: uid, blockedSet: blockedSet });

        return data.set;
    };
};
export = blockFunction;
"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const db = require("../database");
const plugins = require("../plugins");
const cacheCreate = require("../cache/lru");
function blockFunction(User) {
    User.blocks = {
        _cache: cacheCreate({
            name: 'user:blocks',
            max: 100,
            ttl: 0,
        }),
        is: function (targetUid, uids) {
            return __awaiter(this, void 0, void 0, function* () {
                const isArray = Array.isArray(uids);
                uids = isArray ? uids : [uids];
                const blocks = yield User.blocks.list(uids);
                const isBlocked = uids.map((uid, index) => blocks[index].includes(parseInt(targetUid.toString(), 10)));
                return isArray ? isBlocked : isBlocked[0];
            });
        },
        can: function (callerUid, blockerUid, blockeeUid, type) {
            return __awaiter(this, void 0, void 0, function* () {
                // Guests can't block
                if (blockerUid === 0 || blockeeUid === 0) {
                    throw new Error('[[error:cannot-block-guest]]');
                }
                else if (blockerUid === blockeeUid) {
                    throw new Error('[[error:cannot-block-self]]');
                }
                // Administrators and global moderators cannot be blocked
                // Only admins/mods can block users as another user
                const [isCallerAdminOrMod, isBlockeeAdminOrMod] = yield Promise.all([
                    User.isAdminOrGlobalMod(callerUid),
                    User.isAdminOrGlobalMod(blockeeUid),
                ]);
                if (isBlockeeAdminOrMod && type === 'block') {
                    throw new Error('[[error:cannot-block-privileged]]');
                }
                if (parseInt(callerUid.toString(), 10) !== parseInt(blockerUid.toString(), 10) && !isCallerAdminOrMod) {
                    throw new Error('[[error:no-privileges]]');
                }
            });
        },
        list: function (uids) {
            return __awaiter(this, void 0, void 0, function* () {
                const isArray = Array.isArray(uids);
                uids = (isArray ? (Array.isArray(uids) ? uids : [uids]) : [uids]);
                uids = uids.map(uid => parseInt(uid.toString(), 10));
                const cachedData = {};
                const unCachedUids = User.blocks._cache.getUnCachedKeys(uids, cachedData);
                if (unCachedUids.length) {
                    const unCachedData = yield db.getSortedSetsMembers(unCachedUids.map(uid => `uid:${uid}:blocked_uids`));
                    unCachedUids.forEach((uid, index) => {
                        cachedData[uid] = (unCachedData[index] || []).map(uid => parseInt(uid, 10));
                        User.blocks._cache.set(uid, cachedData[uid]);
                    });
                }
                const result = uids.map(uid => cachedData[uid] || []);
                return isArray ? result.slice() : result[0];
            });
        },
        add: function (targetUid, uid) {
            return __awaiter(this, void 0, void 0, function* () {
                yield User.blocks.applyChecks('block', targetUid, uid);
                yield db.sortedSetAdd(`uid:${uid}:blocked_uids`, Date.now(), targetUid);
                yield User.incrementUserFieldBy(uid, 'blocksCount', 1);
                User.blocks._cache.del(parseInt(uid.toString(), 10));
                plugins.hooks.fire('action:user.blocks.add', { uid: uid, targetUid: targetUid });
            });
        },
        remove: function (targetUid, uid) {
            return __awaiter(this, void 0, void 0, function* () {
                yield User.blocks.applyChecks('unblock', targetUid, uid);
                yield db.sortedSetRemove(`uid:${uid}:blocked_uids`, targetUid);
                yield User.decrementUserFieldBy(uid, 'blocksCount', 1);
                User.blocks._cache.del(parseInt(uid.toString(), 10));
                plugins.hooks.fire('action:user.blocks.remove', { uid: uid, targetUid: targetUid });
            });
        },
        applyChecks: function (type, targetUid, uid) {
            return __awaiter(this, void 0, void 0, function* () {
                yield User.blocks.can(uid, uid, targetUid, type);
                const isBlock = type === 'block';
                const is = yield User.blocks.is(targetUid, uid);
                if (is === isBlock) {
                    throw new Error(`[[error:already-${isBlock ? 'blocked' : 'unblocked'}]]`);
                }
            });
        },
        filterUids: function (targetUid, uids) {
            return __awaiter(this, void 0, void 0, function* () {
                const isBlocked = yield User.blocks.is(targetUid, uids);
                return uids.filter((uid, index) => !isBlocked[index]);
            });
        },
        filter: function (uid, property, set) {
            return __awaiter(this, void 0, void 0, function* () {
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
                const blocked_uids = yield User.blocks.list(uid);
                const flatBlockedUids = [].concat(...blocked_uids);
                const blockedSet = new Set(flatBlockedUids);
                set = set.filter(item => !blockedSet.has(parseInt(isPlain ? item : (item && item[property]), 10)));
                const data = yield plugins.hooks.fire('filter:user.blocks.filter', { set: set, property: property, uid: uid, blockedSet: blockedSet });
                return data.set;
            });
        }
    };
}
;
module.exports = blockFunction;

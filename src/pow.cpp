// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "chain.h"
#include "chainparams.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    static const int nMinActualTimespan_Version1 = Params().nAveragingTargetTimespan_Version1 * (100 - Params().nMaxAdjustUp_Version1) / 100;
    static const int nMaxActualTimespan_Version1 = Params().nAveragingTargetTimespan_Version1 * (100 + Params().nMaxAdjustDown_Version1) / 100;
    static const int nMinActualTimespan_Version2 = Params().nAveragingTargetTimespan_Version2 * (100 - Params().nMaxAdjustUp_Version2) / 100;
    static const int nMaxActualTimespan_Version2 = Params().nAveragingTargetTimespan_Version2 * (100 + Params().nMaxAdjustDown_Version2) / 100;
    static const int nMinActualTimespan_Version3 = Params().nAveragingTargetTimespan_Version3 * (100 - Params().nMaxAdjustUp_Version3) / 100;
    static const int nMaxActualTimespan_Version3 = Params().nAveragingTargetTimespan_Version3 * (100 + Params().nMaxAdjustDown_Version3) / 100;

    unsigned int nProofOfWorkLimit = Params().ProofOfWorkLimit().GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    unsigned int nInterval;
    unsigned int nTargetTimespan;
    unsigned int nAveragingInterval;
    unsigned int nMinActualTimespan;
    unsigned int nMaxActualTimespan;
    unsigned int nAveragingTargetTimespan;

    if (pindexLast->nHeight+1 < Params().nHeight_Version2)
    {
        nAveragingInterval = Params().nAveragingInterval_Version1;
        nInterval = Params().nInterval_Version1;
        nTargetTimespan = Params().nTargetTimespan_Version1;
        nMinActualTimespan = nMinActualTimespan_Version1;
        nMaxActualTimespan = nMaxActualTimespan_Version1;
        nAveragingTargetTimespan = Params().nAveragingTargetTimespan_Version1;
    }
    else
    if (pindexLast->nHeight+1 < Params().nHeight_Version3)
    {
        nAveragingInterval = Params().nAveragingInterval_Version2;
        nInterval = Params().nInterval_Version2;
        nTargetTimespan = Params().nTargetTimespan_Version2;
        nMinActualTimespan = nMinActualTimespan_Version2;
        nMaxActualTimespan = nMaxActualTimespan_Version2;
        nAveragingTargetTimespan = Params().nAveragingTargetTimespan_Version2;
    }
    else
    {
        nAveragingInterval = Params().nAveragingInterval_Version3;
        nInterval = Params().nInterval_Version3;
        nTargetTimespan = Params().nTargetTimespan_Version3;
        nMinActualTimespan = nMinActualTimespan_Version3;
        nMaxActualTimespan = nMaxActualTimespan_Version3;
        nAveragingTargetTimespan = Params().nAveragingTargetTimespan_Version3;
    }

    // Only change once per interval
    if ((pindexLast->nHeight+1) % nInterval != 0)
    {
        if (Params().AllowMinDifficultyBlocks())
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + nTargetTimespan*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % nInterval != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Florincoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = nAveragingInterval-1;
    if ((pindexLast->nHeight+1) != nAveragingInterval)
        blockstogoback = nAveragingInterval;

    // Go back by what we want to be nAveragingInterval worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    LogPrintf("  nActualTimespan = %d  before bounds\n", nActualTimespan);
    if (nActualTimespan < nMinActualTimespan)
        nActualTimespan = nMinActualTimespan;
    if (nActualTimespan > nMaxActualTimespan)
        nActualTimespan = nMaxActualTimespan;

    // Retarget
    uint256 bnNew;
    uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Florincoin: intermediate uint256 can overflow by 1 bit
    bool fShift = bnNew.bits() > 235;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= nAveragingTargetTimespan;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > Params().ProofOfWorkLimit())
        bnNew = Params().ProofOfWorkLimit();

    /// debug print
    LogPrintf("GetNextWorkRequired RETARGET\n");
    LogPrintf("Params().TargetTimespan() = %d    nActualTimespan = %d\n", nTargetTimespan, nActualTimespan);
    LogPrintf("Before: %08x  %s\n", pindexLast->nBits, bnOld.ToString());
    LogPrintf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    bool fNegative;
    bool fOverflow;
    uint256 bnTarget;

    if (Params().SkipProofOfWorkCheck())
       return true;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > Params().ProofOfWorkLimit())
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget)
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

uint256 GetBlockProof(const CBlockIndex& block)
{
    uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

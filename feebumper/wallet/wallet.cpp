// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <base58.h>
#include <checkpoints.h>
#include <chain.h>
#include <wallet/coincontrol.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <fs.h>
#include <wallet/init.h>
#include <key.h>
#include <keystore.h>
#include <validation.h>
#include <net.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <scheduler.h>
#include <timedata.h>
#include <txmempool.h>
#include <util.h>
#include <ui_interface.h>
#include <utilmoneystr.h>
#include <wallet/fees.h>

#include <assert.h>
#include <future>

#include <boost/algorithm/string/replace.hpp>
#include <boost/thread.hpp>

std::vector<CWalletRef> vpwallets;
/** Transaction fee set by the user */
CFeeRate payTxFee(DEFAULT_TRANSACTION_FEE);
unsigned int nTxConfirmTarget = DEFAULT_TX_CONFIRM_TARGET;
bool bSpendZeroConfChange = DEFAULT_SPEND_ZEROCONF_CHANGE;
bool fWalletRbf = DEFAULT_WALLET_RBF;

const char * DEFAULT_WALLET_DAT = "wallet.dat";
const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;

/**
 * Fees smaller than this (in satoshi) are considered zero fee (for transaction creation)
 * Override with -mintxfee
 */
CFeeRate CWallet::minTxFee = CFeeRate(DEFAULT_TRANSACTION_MINFEE);
/**
 * If fee estimation does not have enough data to provide estimates, use this fee instead.
 * Has no effect if not using fee estimation
 * Override with -fallbackfee
 */
CFeeRate CWallet::fallbackFee = CFeeRate(DEFAULT_FALLBACK_FEE);

CFeeRate CWallet::m_discard_rate = CFeeRate(DEFAULT_DISCARD_FEE);

const uint256 CMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

CAmount CWalletTx::GetDebit(const isminefilter& filter) const
{
    if (tx->vin.empty())
        return 0;

    CAmount debit = 0;
    if(filter & ISMINE_SPENDABLE)
    {
        if (fDebitCached)
            debit += nDebitCached;
        else
        {
            nDebitCached = pwallet->GetDebit(*tx, ISMINE_SPENDABLE);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if(filter & ISMINE_WATCH_ONLY)
    {
        if(fWatchDebitCached)
            debit += nWatchDebitCached;
        else
        {
            nWatchDebitCached = pwallet->GetDebit(*tx, ISMINE_WATCH_ONLY);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CAmount CWallet::GetDebit(const CTransaction& tx, const isminefilter& filter) const
{
	CAmount nDebit = 0;
	for (const CTxIn& txin : tx.vin)
		{
		nDebit += GetDebit(txin, filter);
		if (!MoneyRange(nDebit))
			throw std::runtime_error(std::string(__func__) + ": value out of range");
		}
	return nDebit;
}

// Note that this function doesn't distinguish between a 0-valued input,
// and a not-"is mine" (according to the filter) input.
CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter) const
{
	{
	LOCK(cs_wallet);
	std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
	if (mi != mapWallet.end())
		{
		const CWalletTx& prev = (*mi).second;
		if (txin.prevout.n < prev.tx->vout.size())
			if (IsMine(prev.tx->vout[txin.prevout.n]) & filter)
				return prev.tx->vout[txin.prevout.n].nValue;
		}
	}
	return 0;
}

isminetype CWallet::IsMine(const CTxOut& txout) const
{
	return ::IsMine(*this, txout.scriptPubKey);
}



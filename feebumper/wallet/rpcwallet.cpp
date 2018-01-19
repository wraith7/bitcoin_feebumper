// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <base58.h>
#include <chain.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <httpserver.h>
#include <validation.h>
#include <net.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <rpc/mining.h>
#include <rpc/safemode.h>
#include <rpc/server.h>
#include <script/sign.h>
#include <timedata.h>
#include <util.h>
#include <utilmoneystr.h>
#include <wallet/coincontrol.h>
#include <wallet/feebumper.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <init.h>  // For StartShutdown

#include <stdint.h>

#include <univalue.h>

static const std::string WALLET_ENDPOINT_BASE = "/wallet/";

// 이미 mempool에 들어가있는 tx에서 돌려받는 change를 줄이는 방식으로 fee를 증가시켜 block에 반영될 확률을 높임.
// 만약에 되돌려 받는 change가 증가된 fee를 커버할 정도로 크지 않으면 실패.
// 또한, 기존에 존재하던 트랜잭션의 output을 사용하는 트랜잭션이 wallet이나 mempool에 있어도 실패.
//
UniValue bumpfee(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "bumpfee \"txid\" ( options ) \n"
            "\nBumps the fee of an opt-in-RBF transaction T, replacing it with a new transaction B.\n"
            "An opt-in RBF transaction with the given txid must be in the wallet.\n"
            "The command will pay the additional fee by decreasing (or perhaps removing) its change output.\n"
            "If the change output is not big enough to cover the increased fee, the command will currently fail\n"
            "instead of adding new inputs to compensate. (A future implementation could improve this.)\n"
            "The command will fail if the wallet or mempool contains a transaction that spends one of T's outputs.\n"
            "By default, the new fee will be calculated automatically using estimatefee.\n"
            "The user can specify a confirmation target for estimatefee.\n"
            "Alternatively, the user can specify totalFee, or use RPC settxfee to set a higher fee rate.\n"
            "At a minimum, the new fee rate must be high enough to pay an additional new relay fee (incrementalfee\n"
            "returned by getnetworkinfo) to enter the node's mempool.\n"
            "\nArguments:\n"
            "1. txid                  (string, required) The txid to be bumped\n"
            "2. options               (object, optional)\n"
            "   {\n"
            "     \"confTarget\"        (numeric, optional) Confirmation target (in blocks)\n"
            "     \"totalFee\"          (numeric, optional) Total fee (NOT feerate) to pay, in satoshis.\n"
            "                         In rare cases, the actual fee paid might be slightly higher than the specified\n"
            "                         totalFee if the tx change output has to be removed because it is too close to\n"
            "                         the dust threshold.\n"
            "     \"replaceable\"       (boolean, optional, default true) Whether the new transaction should still be\n"
            "                         marked bip-125 replaceable. If true, the sequence numbers in the transaction will\n"
            "                         be left unchanged from the original. If false, any input sequence numbers in the\n"
            "                         original transaction that were less than 0xfffffffe will be increased to 0xfffffffe\n"
            "                         so the new transaction will not be explicitly bip-125 replaceable (though it may\n"
            "                         still be replaceable in practice, for example if it has unconfirmed ancestors which\n"
            "                         are replaceable).\n"
            "     \"estimate_mode\"     (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
            "         \"UNSET\"\n"
            "         \"름\"\n"
            "         \"CONSERVATIVE\"\n"
            "   }\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\":    \"value\",   (string)  The id of the new transaction\n"
            "  \"origfee\":  n,         (numeric) Fee of the replaced transaction\n"
            "  \"fee\":      n,         (numeric) Fee of the new transaction\n"
            "  \"errors\":  [ str... ] (json array of strings) Errors encountered during processing (may be empty)\n"
            "}\n"
            "\nExamples:\n"
            "\nBump the fee, get the new transaction\'s txid\n" +
            HelpExampleCli("bumpfee", "<txid>"));
    }

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VOBJ});
    uint256 hash;
	  // 원래의 txid를 input으로 받음
    hash.SetHex(request.params[0].get_str());

    // optional parameters
    CAmount totalFee = 0;
    CCoinControl coin_control;
	  //signalRbf가 true여야 BIP125를 따름
    coi름_control.signalRbf = true;
    if (!request.params[1].isNull()) {
        UniValue options = request.params[1];
        RPCTypeCheckObj(options,
            {
                {"confTarget", UniValueType(UniValue::VNUM)},
                {"totalFee", UniValueType(UniValue::VNUM)},
                {"replaceable", UniValueType(UniValue::VBOOL)},
                {"estimate_mode", UniValueType(UniValue::VSTR)},
            },
            true, true);

        if (options.exists("confTarget") && options.exists("totalFee")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "confTarget and totalFee options should not both be set. Please provide either a confirmation target for fee estimation or an explicit total fee for the transaction.");
        } else if (options.exists("confTarget")) { // TODO: alias this to conf_target
            coin_control.m_confirm_target = ParseConfirmTarget(options["confTarget"]);
        } else if (options.exists("totalFee")) {
            totalFee = options["totalFee"].get_int64();
            if (totalFee <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid totalFee %s (must be greater than 0)", FormatMoney(totalFee)));
            }
        }

        if (options.exists("replaceable")) {
            coin_control.signalRbf = options["replaceable"].get_bool();
        }
        if (options.exists("estimate_mode")) {
            if (!FeeModeFromString(options["estimate_mode"].get_str(), coin_control.m_fee_mode)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
            }
        }
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);


    std::vector<std::string> errors;
    CAmount old_fee;
    CAmount new_fee;
    CMutableTransaction mtx;
    feebumper::Result res = feebumper::CreateTransaction(pwallet, hash, coin_control, totalFee, errors, old_fee, new_fee, mtx);
    if (res != feebumper::Result::OK) {
        switch(res) {
            case feebumper::Result::INVALID_ADDRESS_OR_KEY:
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errors[0]);
                break;
            case feebumper::Result::INVALID_REQUEST:
                throw JSONRPCError(RPC_INVALID_REQUEST, errors[0]);
                break;
            case feebumper::Result::INVALID_PARAMETER:
                throw JSONRPCError(RPC_INVALID_PARAMETER, errors[0]);
                break;
            case feebumper::Result::WALLET_ERROR:
                throw JSONRPCError(RPC_WALLET_ERROR, errors[0]);
                break;
            default:
                throw JSONRPCError(RPC_MISC_ERROR, errors[0]);
                break;
        }
    }

    // sign bumped transaction
    if (!feebumper::SignTransaction(pwallet, mtx)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Can't sign transaction.");
    }
    // commit the bumped transaction
    uint256 txid;
    if (feebumper::CommitTransaction(pwallet, hash, std::move(mtx), errors, txid) != feebumper::Result::OK) {
        throw JSONRPCError(RPC_WALLET_ERROR, errors[0]);
    }
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("txid", txid.GetHex()));
    result.push_back(Pair("origfee", ValueFromAmount(old_fee)));
    result.push_back(Pair("fee", ValueFromAmount(new_fee)));
    UniValue result_errors(UniValue::VARR);
    for (const std::string& error : errors) {
        result_errors.push_back(error);
    }
    result.push_back(Pair("errors", result_errors));

    return result;
}

extern UniValue abortrescan(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue dumpprivkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue importprivkey(const JSONRPCRequest& request);
extern UniValue importaddress(const JSONRPCRequest& request);
extern UniValue importpubkey(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);
extern UniValue importprunedfunds(const JSONRPCRequest& request);
extern UniValue removeprunedfunds(const JSONRPCRequest& request);
extern UniValue importmulti(const JSONRPCRequest& request);
extern UniValue rescanblockchain(const JSONRPCRequest& request);

static const CRPCCommand commands[] =
{ //  category              name                        actor (function)           argNames
    //  --------------------- ------------------------    -----------------------  ----------
    { "rawtransactions",    "fundrawtransaction",       &fundrawtransaction,       {"hexstring","options"} },
    { "hidden",             "resendwallettransactions", &resendwallettransactions, {} },
    { "wallet",             "abandontransaction",       &abandontransaction,       {"txid"} },
    { "wallet",             "abortrescan",              &abortrescan,              {} },
    { "wallet",             "addmultisigaddress",       &addmultisigaddress,       {"nrequired","keys","account"} },
    { "wallet",             "addwitnessaddress",        &addwitnessaddress,        {"address","p2sh"} },
    { "wallet",             "backupwallet",             &backupwallet,             {"destination"} },
    { "wallet",             "bumpfee",                  &bumpfee,                  {"txid", "options"} },
    { "wallet",             "dumpprivkey",              &dumpprivkey,              {"address"}  },
    { "wallet",             "dumpwallet",               &dumpwallet,               {"filename"} },
    { "wallet",             "encryptwallet",            &encryptwallet,            {"passphrase"} },
    { "wallet",             "getaccountaddress",        &getaccountaddress,        {"account"} },
    { "wallet",             "getaccount",               &getaccount,               {"address"} },
    { "wallet",             "getaddressesbyaccount",    &getaddressesbyaccount,    {"account"} },
    { "wallet",             "getbalance",               &getbalance,               {"account","minconf","include_watchonly"} },
    { "wallet",             "getnewaddress",            &getnewaddress,            {"account"} },
    { "wallet",             "getrawchangeaddress",      &getrawchangeaddress,      {} },
    { "wallet",             "getreceivedbyaccount",     &getreceivedbyaccount,     {"account","minconf"} },
    { "wallet",             "getreceivedbyaddress",     &getreceivedbyaddress,     {"address","minconf"} },
    { "wallet",             "gettransaction",           &gettransaction,           {"txid","include_watchonly"} },
    { "wallet",             "getunconfirmedbalance",    &getunconfirmedbalance,    {} },
    { "wallet",             "getwalletinfo",            &getwalletinfo,            {} },
    { "wallet",             "importmulti",              &importmulti,              {"requests","options"} },
    { "wallet",             "importprivkey",            &importprivkey,            {"privkey","label","rescan"} },
    { "wallet",             "importwallet",             &importwallet,             {"filename"} },
    { "wallet",             "importaddress",            &importaddress,            {"address","label","rescan","p2sh"} },
    { "wallet",             "importprunedfunds",        &importprunedfunds,        {"rawtransaction","txoutproof"} },
    { "wallet",             "importpubkey",             &importpubkey,             {"pubkey","label","rescan"} },
    { "wallet",             "keypoolrefill",            &keypoolrefill,            {"newsize"} },
    { "wallet",             "listaccounts",             &listaccounts,             {"minconf","include_watchonly"} },
    { "wallet",             "listaddressgroupings",     &listaddressgroupings,     {} },
    { "wallet",             "listlockunspent",          &listlockunspent,          {} },
    { "wallet",             "listreceivedbyaccount",    &listreceivedbyaccount,    {"minconf","include_empty","include_watchonly"} },
    { "wallet",             "listreceivedbyaddress",    &listreceivedbyaddress,    {"minconf","include_empty","include_watchonly"} },
    { "wallet",             "listsinceblock",           &listsinceblock,           {"blockhash","target_confirmations","include_watchonly","include_removed"} },
    { "wallet",             "listtransactions",         &listtransactions,         {"account","count","skip","include_watchonly"} },
    { "wallet",             "listunspent",              &listunspent,              {"minconf","maxconf","addresses","include_unsafe","query_options"} },
    { "wallet",             "listwallets",              &listwallets,              {} },
    { "wallet",             "lockunspent",              &lockunspent,              {"unlock","transactions"} },
    { "wallet",             "move",                     &movecmd,                  {"fromaccount","toaccount","amount","minconf","comment"} },
    { "wallet",             "sendfrom",                 &sendfrom,                 {"fromaccount","toaddress","amount","minconf","comment","comment_to"} },
    { "wallet",             "sendmany",                 &sendmany,                 {"fromaccount","amounts","minconf","comment","subtractfeefrom","replaceable","conf_target","estimate_mode"} },
    { "wallet",             "sendtoaddress",            &sendtoaddress,            {"address","amount","comment","comment_to","subtractfeefromamount","replaceable","conf_target","estimate_mode"} },
    { "wallet",             "setaccount",               &setaccount,               {"address","account"} },
    { "wallet",             "settxfee",                 &settxfee,                 {"amount"} },
    { "wallet",             "signmessage",              &signmessage,              {"address","message"} },
    { "wallet",             "walletlock",               &walletlock,               {} },
    { "wallet",             "walletpassphrasechange",   &walletpassphrasechange,   {"oldpassphrase","newpassphrase"} },
    { "wallet",             "walletpassphrase",         &walletpassphrase,         {"passphrase","timeout"} },
    { "wallet",             "removeprunedfunds",        &removeprunedfunds,        {"txid"} },
    { "wallet",             "rescanblockchain",         &rescanblockchain,         {"start_height", "stop_height"} },

    { "generating",         "generate",                 &generate,                 {"nblocks","maxtries"} },
};

void RegisterWalletRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

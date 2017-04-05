%%%-------------------------------------------------------------------
%%% @author simonxu
%%% @copyright (C) 2016, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 20. Apr 2016 15:14
%%%-------------------------------------------------------------------
-module(utils_pk).
-include_lib("eunit/include/eunit.hrl").
-author("simonxu").

%% API
-export([
  load_private_key/1
  , load_private_key/2
  , load_public_key/1
  , load_mcht_private_key/2
  , load_mcht_public_key/2
  , up_sign/2
  , up_sign_string/3
  , up_sign_msg/3
  , up_verify_msg/3
  , digest_string/1
  , mcht_sign_msg/3
  , mcht_sign_string/3
  , mcht_verify_sig/3
]).

%%-define(MCHT_KEY_LOC, "/keys/mcht/").

%%==================================================================
-spec load_mcht_private_key(MchtId, Direction) -> {ok, any()} when
  MchtId :: integer(),
  Direction :: req|resp.

load_mcht_private_key(MchtId, Direction) when is_integer(MchtId) ->
  % 定位商户秘钥所在目录
  MchtKeyDir = keyfile_dir(MchtId, Direction),
  KeyFileName = lists:flatten([MchtKeyDir, "/private_key.pem"]),
  lager:debug("KeyFileName=~p", [KeyFileName]),
  load_private_key(KeyFileName).

%%==================================================================
load_mcht_public_key(MchtId, Direction) when is_integer(MchtId) ->
  % 定位商户秘钥所在目录
  MchtKeyDir = keyfile_dir(MchtId, Direction),
  KeyFileName = [MchtKeyDir, "/public_key.pem"],
  lager:debug("KeyFileName=~p", [KeyFileName]),
  load_private_key(KeyFileName).

%%==================================================================
keyfile_dir(MchtId, Direction) ->
  MchtKeyBaseDir = rfe_utils_env:get_path([home, priv_dir, mcht_keys_dir]),
  MchtKeyDir = [MchtKeyBaseDir
    , "/"
    , integer_to_list(MchtId)
    , "/"
    , atom_to_list(Direction)
  ],
  MchtKeyDir.


%%==================================================================
load_private_key(KeyFileName) ->
  load_private_key(KeyFileName, "").

load_private_key(KeyFileName, Pwd) ->
  {ok, PemBin} = file:read_file(KeyFileName),
  [RSAEntry | _Rest] = public_key:pem_decode(PemBin),
  RsaKeyInfo = public_key:pem_entry_decode(RSAEntry, Pwd),
  lager:debug("private key = ~p", [RsaKeyInfo]),
  {ok, RsaKeyInfo}.


%%==================================================================
load_public_key(KeyFileName) ->
  {ok, PemBin} = file:read_file(KeyFileName),
  [Certificate] = public_key:pem_decode(PemBin),
  PublicKey = public_key:pem_entry_decode(Certificate),
  lager:debug("public key = ~p", [PublicKey]),
  {ok, PublicKey}.

%%==================================================================
-spec up_sign_string(M, Model, FieldList) -> Sig when
  M :: atom(),
  Model :: model_up_req_pay:req_up() | model_up_resp_pay:resp_up(),
  FieldList :: [model_up_req_pay:req_up_fields()] |
  [model_up_resp_pay:resp_up_fields()],
  Sig :: model_up_req_pay:up_signature().

up_sign_string(M, Model, FieldList) when is_atom(M), is_list(FieldList) ->
  A = [
    prepare_one_sign_field(X, M:get(Model, X))
    || X <- FieldList
  ],
  list_to_binary(A).

prepare_one_sign_field(version = X, Value) ->
  [atom_to_list(X), <<"=">>, Value];
prepare_one_sign_field(_X, <<>>) ->
  % if field value is empty, not put in sign_string
  [];
prepare_one_sign_field(X, Value) when is_integer(Value) ->
  [atom_to_list(X), <<"=">>, integer_to_binary(Value), <<"&">>];
prepare_one_sign_field(X, Value) when is_binary(Value);is_list(Value) ->
  [atom_to_list(X), <<"=">>, Value, <<"&">>].
%%==================================================================
-spec up_sign(binary(), tuple()) -> binary().
up_sign(Bin, Key) ->
  %S = public_key:sign({digest,Bin},'sha',Key),
  S = public_key:sign(Bin, 'sha', Key),
  B = base64:encode(S),
  B.

up_sign_test() ->
  Key = unionpay_config:privateKey(999),
  DigestBin = <<"c527432e8f632d555c651eaf8e5e0b027405fa46">>,
  SignResult = up_sign(DigestBin, Key),
  ?assertEqual(SignResult, <<"hLrvwNR5lHtQUKU/tXvwY857BKbKOQCGrKbLcg/68ZIG04yGnMFcmKUOO/cAt7SREoyjbOmSR6FUficTeofXZr7arrujbtyBB3wolmQ0BKTAVA7jjYaaYmMQxRkSlMElX7kYSsZyqCAzIzDkqKA36nN9w5g2wur3fbkha7GPyIw=">>),
  ok.

%%==================================================================
-spec digest_string_upper(binary()) -> binary().
digest_string_upper(Bin) ->
  DigestBin = crypto:hash(sha, Bin),
  DigestHex = xfutils:bin_to_hex(DigestBin),
  % convert to lowercase
  DigestHex.


%%==================================================================
-spec digest_string(binary()) -> binary().
digest_string(Bin) ->
  U = digest_string_upper(Bin),
  list_to_binary(string:to_lower(binary_to_list(U))).

digest_string_test() ->
  A = <<"accNo=6225682141000002950&accessType=0&backUrl=https://101.231.204.80:5000/gateway/api/backTransReq.do&bizType=000201&certId=124876885185794726986301355951670452718&channelType=07&currencyCode=156&encoding=UTF-8&merId=898340183980105&orderId=2014110600007615&signMethod=01&txnAmt=000000010000&txnSubType=01&txnTime=20150109135921&txnType=01&version=5.0.0">>,

  ?assertEqual(digest_string(A), <<"c527432e8f632d555c651eaf8e5e0b027405fa46">>).

%%==================================================================
-spec up_sign_msg(M, Model, FieldList) -> Sig when
  M :: atom(),
  Model :: model_up_req_pay:req_up() | model_up_resp_pay:resp_up(),
  FieldList :: [model_up_req_pay:req_up_fields()] |
  [model_up_resp_pay:resp_up_fields()],
  Sig :: model_up_req_pay:up_signature().

up_sign_msg(M, Model, SignFields) when is_atom(M), is_list(SignFields) ->
  MerId = M:get(Model, merId),
  ShortMerId = unionpay_config:short_mer_id(MerId),
  SignString = up_sign_string(M, Model, SignFields),
  lager:debug("SignString =~ts", [SignString]),
  DigestBin = digest_string(SignString),
  Key = unionpay_config:privateKey(ShortMerId),
  SignBin = up_sign(DigestBin, Key),
  SignBin.

%%=============================================================================
-spec signature_decode(binary()) -> binary().
signature_decode(Signature) ->
  base64:decode(Signature).
%%==================================================================
-spec up_verify_msg(M, Model, FieldList) -> boolean() when
  M :: atom(),
  Model :: model_up_req_pay:req_up()| model_up_resp_pay:resp_up()| model_up_resp_query:up_resp_query(),
  FieldList :: [model_up_req_pay:req_up_fields()] |
  [model_up_resp_pay:resp_up_fields()].

up_verify_msg(M, Model, SignFields) when is_atom(M), is_list(SignFields) ->
  SignString = up_sign_string(M, Model, SignFields),
  lager:debug("SignString = ~ts", [SignString]),
  DigestResp = digest_string(SignString),

  %#?UP_RESP{signature = Signature} = UpResp,
  Signature = M:get(Model, signature),
  SignatureDecode = signature_decode(Signature),
  PK = unionpay_config:public_key(),
  lager:debug("Resp's sign string digesst = ~ts~n,signature = ~ts", [DigestResp, Signature]),

  VerifyRet = public_key:verify(DigestResp, sha, SignatureDecode, PK),
  case VerifyRet of
    true -> ok;
    false ->
      % verify fail
      UpIndexKey = M:get(Model, up_index_key),
      lager:error("Up Txn ~p sig verify failed. SignString = ~p,Sig = ~p",
        [UpIndexKey, SignString, Signature]),
      fail
  end.

%%==================================================================
-spec mcht_sign_msg(M, Model, FieldList) -> {SignStr, Sig} when
  M :: atom(),
  Model :: model_mcht_req_pay:req_mcht() | model_mcht_resp_pay:resp_mcht(),
  FieldList :: [model_mcht_req_pay:req_mcht_fields() |
  model_mcht_resp_pay:resp_mcht_fields()],
  SignStr :: binary(),
  Sig :: model_mcht_req_pay:mcht_signature().


mcht_sign_msg(M, Model, SignFields) when is_atom(M), is_list(SignFields) ->
  MchtId = M:get(Model, mcht_id),
  SignString = mcht_sign_string(M, Model, SignFields),

  Direction = sign_mcht_direction(M),
  Sig = rf_enc:sign_hex(binary_to_integer(MchtId), Direction, SignString),
  lager:debug("In mcht resp, SignString = ~ts,Sig = ~p", [SignString, Sig]),
  {SignString, Sig}.

%%==================================================================
sign_mcht_direction(model_mcht_req_refund) ->
  req;
sign_mcht_direction(model_mcht_resp_refund) ->
  resp;
sign_mcht_direction(model_mcht_info_refund) ->
  resp;
sign_mcht_direction(model_mcht_req_query) ->
  req;
sign_mcht_direction(model_mcht_resp_query) ->
  resp;
sign_mcht_direction(model_mcht_req_pay) ->
  req;
sign_mcht_direction(model_mcht_resp_pay) ->
  resp.


%%==================================================================
-spec mcht_sign_string(M, Model, FieldList) -> SignString when
  M :: atom(),
  Model :: model_mcht_req_pay:req_mcht() | model_mcht_resp_pay:resp_mcht(),
  FieldList :: [model_mcht_req_pay:req_mcht_fields() |
  model_mcht_resp_pay:resp_mcht_fields()],
  SignString :: binary().

mcht_sign_string(M, Model, SignFields) when is_atom(M), is_list(SignFields) ->
  A = [
    value_for_sign(M:get(Model, X))
    || X <- SignFields
  ],
  list_to_binary(A).

value_for_sign(undefined) ->
  <<>>;
value_for_sign(Value) when is_integer(Value) ->
  integer_to_binary(Value);
value_for_sign(Value) ->
  Value.

-define(REQ_SIGN_FIELDS, [
  mcht_id
  , mcht_txn_date
  , mcht_txn_seq
  , mcht_txn_time
  , mcht_txn_amt
  , bank_id
  , mcht_order_desc
  , gateway_id
  , mcht_back_url
  , mcht_front_url
  , prod_id
  , prod_memo
  , prod_bank_acct_id
  , prod_bank_acct_corp_name
  , prod_bank_name

]).

%%sign_string_test() ->
%%  PropList = [
%%    {<<"tranAmt">>, <<"10000">>}
%%    , {<<"orderDesc">>, <<"{pI=131026}"/utf8>>}
%%    , {<<"orderId">>, <<"1460028751003">>}
%%    , {<<"merchId">>, <<"000121">>}
%%    , {<<"tranId">>, <<"193231">>}
%%    , {<<"prodId">>, <<"131026">>}
%%    , {<<"tranDate">>, <<"20160407">>}
%%    , {<<"tranTime">>, <<"193231">>}
%%    , {<<"accountId">>, <<"03429500040006212">>}
%%    , {<<"accountName">>, <<"上海聚孚金融信息服务有限公司"/utf8>>}
%%    , {<<"accountBank">>, <<"6225220113392775">>}
%%    , {<<"signature">>, <<"test">>}
%%    , {<<"gateWayId">>, <<"1002">>}
%%    , {<<"trustFrontUrl">>, <<"http://test.trust-one.com/payment_success/148641458285747438">>}
%%    , {<<"trustBackUrl">>, <<"http://test.trust-one.com/dapi/gateWay/pay/notice">>}
%%    , {<<"bankId">>, <<"ICBCD">>}
%%  ],
%%  {ok, MchtReq} = model_mcht_req_pay:new(PropList),
%%  SignString = mcht_sign_string(model_mcht_req_pay, MchtReq, ?REQ_SIGN_FIELDS),
%%  %ExpectString = <<"00012120160407193231193231146002875100303429500040006212%E4%B8%8A%E6%B5%B7%E8%81%9A%E5%AD%9A%E9%87%91%E8%9E%8D%E4%BF%A1%E6%81%AF%E6%9C%8D%E5%8A%A1%E6%9C%89%E9%99%90%E5%85%AC%E5%8F%B86225220113392775100{pI=131026}1002http://test.trust-one.com/dapi/gateWay/pay/noticehttp://test.trust-one.com/dapi/gateWay/pay/notice131026ICBCD"/utf8>>,
%%  ExpectString = <<"0001212016040719323119323110000ICBCD{pI=131026}1002http://test.trust-one.com/dapi/gateWay/pay/noticehttp://test.trust-one.com/payment_success/14864145828574743813102603429500040006212上海聚孚金融信息服务有限公司6225220113392775"/utf8>>,
%%  lager:debug("~nSignString = ~ts", [SignString]),
%%  lager:debug("~nExpectSignString = ~ts", [ExpectString]),
%%  ?assertEqual(SignString, ExpectString).

%% test
string_utf8_test() ->
  PL = [{<<"orderDesc">>, <<"{pI=test,aI=03429500040006212,aN=上海聚孚金融信息服务有限公司,aB=农业银行上海张江集电港支行}"/utf8>>}],
  {_, P1} = proplists:lookup(<<"orderDesc">>, PL),
  A = <<"{pI=test,aI=03429500040006212,aN=上海聚孚金融信息服务有限公司,aB=农业银行上海张江集电港支行}"/utf8>>,
  ?assertEqual(A, P1),
  ok.

%%==================================================================
-spec mcht_verify_sig(M, Model, FieldList) -> Sig when
  M :: atom(),
  Model :: model_mcht_req_pay:req_mcht() | model_mcht_resp_pay:resp_mcht()| map(),
  FieldList :: list(),
  Sig :: model_mcht_req_pay:mcht_signature().

mcht_verify_sig(M, Model, SignFields) when is_atom(M), is_list(SignFields) ->
  MchtId = M:get(Model, mcht_id),
  SignString = mcht_sign_string(M, Model, SignFields),
  Signature = M:get(Model, signature),
  lager:debug("In mcht req, SignString = ~ts,Sig = ~p", [SignString, Signature]),


  Direction = sign_mcht_direction(M),

  case rf_enc:verify_hex(binary_to_integer(MchtId),
    Direction, SignString, Signature) of
    true -> ok;
    false ->
      % verify fail
      TxnDate = M:get(Model, mcht_txn_date),
      TxnSeq = M:get(Model, mcht_txn_seq),
      lager:error("sig verify failed. SignString = ~p,Sig = ~p", [SignString, Signature]),
      fail
    %throw({sig_verify_failed, {MchtId, TxnDate, TxnSeq, SignString, Signature}})
  end.


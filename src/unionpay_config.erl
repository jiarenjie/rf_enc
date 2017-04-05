%%%-------------------------------------------------------------------
%%% @author simonxu
%%% @copyright (C) 2016, <COMPANY>
%%% @doc 封装银联在线的相关参数
%%%
%%% @end
%%% Created : 24. Mar 2016 2:37 PM
%%%-------------------------------------------------------------------
-module(unionpay_config).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").
-author("simonxu").

-define(APP, payment_gateway).

-type applied_up_mcht_id_short() :: 18|19|232|234|240|242|999|888.
-type gateway_id() :: binary().
-type applied_up_mcht_id() :: binary().

%% API
-export([
  certId/1
  , mchtId/1
  , privateKey/1
  , mapGateway2Mcht/1
  , channelType/1
  , frontUrl/0
  , backUrl/0
  , public_key/0
  , short_mer_id/1
  , mer_list/0
]).
-compile(export_all).


-spec channelType(applied_up_mcht_id_short()) -> binary().
channelType(ShortId)
  when ShortId =:= 999
  ; ShortId =:= 240
  ; ShortId =:= 234
  ; ShortId =:= 19

  ->
  <<"07">>;
channelType(ShortId)
  when ShortId =:= 242
  ; ShortId =:= 232
  ; ShortId =:= 18

  ->
  <<"08">>.

%%channelType(999) ->
%%  <<"07">>;
%%channelType(242) ->
%%  <<"08">>;
%%channelType(240) ->
%%  <<"07">>;
%%channelType(232) ->
%%  <<"08">>;
%%channelType(234) ->
%%  <<"07">>.

-spec certId(applied_up_mcht_id_short()) -> binary().
certId(18) ->
  <<"70481187397">>;
%%  <<"68759663125">>;
certId(19) ->
  <<"70469027189">>;
%%  <<"68759663125">>;
certId(234) ->
  <<"69567322259">>;
certId(232) ->
  <<"69567322262">>;
certId(242) ->
  <<"69560910632">>;
certId(240) ->
  <<"69567322249">>.

-spec mchtId(applied_up_mcht_id_short()) -> applied_up_mcht_id().
mchtId(999) ->
  <<"898319849000018">>;
%%  <<"898350249000232">>;
mchtId(18) ->
  <<"898319849000018">>;
mchtId(19) ->
  <<"898319849000019">>;
mchtId(232) ->
  <<"898350249000232">>;
mchtId(234) ->
  <<"898350249000234">>;
mchtId(242) ->
  <<"898350249000242">>;
mchtId(240) ->
  <<"898350249000240">>.

-spec short_mer_id(applied_up_mcht_id()) -> applied_up_mcht_id_short().
short_mer_id(<<"898319849000018">>) ->
  18;
short_mer_id(<<"898319849000019">>) ->
  19;
short_mer_id(<<"898350249000232">>) ->
  232;
short_mer_id(<<"898350249000234">>) ->
  234;
short_mer_id(<<"898350249000240">>) ->
  240;
short_mer_id(<<"898350249000242">>) ->
  242.

-spec mapGateway2Mcht(gateway_id()) -> applied_up_mcht_id_short().
mapGateway2Mcht(<<"999">>) ->
  999;
%% jf gateway
mapGateway2Mcht(<<"1002">>) ->
  242;
%% jf wap
mapGateway2Mcht(<<"1003">>) ->
  240;
mapGateway2Mcht(<<"1004">>) ->
  234;
mapGateway2Mcht(<<"1005">>) ->
  232.


-spec keyFile(applied_up_mcht_id_short()) -> string().
keyFile(888) ->
  % 888 means public key
  "acp.pem";
keyFile(999) ->
  "test.pem";
keyFile(18) ->
  "cfca-key-18-pwd-111111.key";
%%  "acp-test-pwd-111111.key";
keyFile(19) ->
  "cfca-key-19-pwd-111111.key";
%%  "acp-test-pwd-111111.key";
keyFile(232) ->
  "cfca-key-232-pwd-111111.key";
keyFile(240) ->
  "cfca-key-240-pwd-111111.key";
keyFile(242) ->
  "cfca-key-242-pwd-111111.key";
keyFile(234) ->
  "cfca-key-234-pwd-111111.key".

-spec keyPwd(applied_up_mcht_id_short()) -> string().
keyPwd(ShortId) ->
  "111111".

%%keyPwd(999) ->
%%  "111111";
%%keyPwd(18) ->
%%  "111111";
%%keyPwd(18) ->
%%  "111111";
%%keyPwd(232) ->
%%  "111111";
%%keyPwd(234) ->
%%  "111111";
%%keyPwd(240) ->
%%  "111111";
%%keyPwd(242) ->
%%  "111111".

-spec keyFileName(applied_up_mcht_id_short()) -> string().
keyFileName(ShortMchtId) ->
  FileName = keyFile(ShortMchtId),
  UpKeysDir = rfe_utils_env:get_path([home, priv_dir, up_keys_dir]),
  filename:join(UpKeysDir, FileName).


-spec privateKey(applied_up_mcht_id_short()) -> public_key:rsa_private_key().
privateKey(ShortMchtId) ->
  KeyFileName = keyFileName(ShortMchtId),
  lager:debug("Get Key from: ~s", [KeyFileName]),
  get_private_key(KeyFileName, keyPwd(ShortMchtId)).

get_private_key(KeyFileName, Pwd) ->
  {ok, PemBin} = file:read_file(KeyFileName),
  [RSAEntry | _Rest] = public_key:pem_decode(PemBin),
  RsaKeyInfo = public_key:pem_entry_decode(RSAEntry, Pwd),
  RsaKey = public_key:der_decode('RSAPrivateKey', RsaKeyInfo#'PrivateKeyInfo'.privateKey),
  RsaKey.

privateKey_test() ->
  Key = privateKey(232),


  ?assertEqual(Key#'RSAPrivateKey'.prime1, 164910897214279990793565655797790731530384922136284441198218055115076018459173827776008320978589025692290426942405062634730664010744210877961285913571931407493150474624273918992053271286936221893137379327875181534232058573063117262634126044633927003585578646554429174751239433279458971404726522662155893190021).

public_key() ->
  PKFile = keyFileName(888),
  {ok, PemBin} = file:read_file(PKFile),
  [Certificate] = public_key:pem_decode(PemBin),
  {_, DerCert, _} = Certificate,
  Decoded = public_key:pkix_decode_cert(DerCert, otp),
  PublicKey = Decoded#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subjectPublicKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey,
  PublicKey.

public_key_test() ->
  PK = public_key(),
  ?assertEqual(PK#'RSAPublicKey'.modulus, 22907886786771678700303006629421459838279797961073316009749504109710262022463827630234615210057922891239935293562631844638675916611762790424446647048480132856908165633282876228841852794927581395542158439208191498566959060460509929659377182667762722220868174601163824777072428789936656414010212886348182815950713123220487941355674661789055899823439732072410608078450441300370660542297756768632531836734900959980831060896098085809924326778586600200899657737604482305128833412256348877032814185118287694441804122671004658390604708231520763282695866721993885132599383244176183080016256735342126523352947110422848743288919).




-spec frontUrl() -> binary().
frontUrl() ->
%%	io:format("~nCurrent Application = ~p~n", [application:get_application()]),
  lager:debug("Current Application = ~p", [application:get_application()]),
  %{ok, FrontUrl} = application:get_env(up_front_url),
  %FrontUrl.
  case application:get_env(up_front_url) of
    {ok, FrontUrl} -> FrontUrl;
    undefined -> "http://localhost:8888/pg/pay_succ"
  end.


-spec backUrl() -> binary().
backUrl() ->
  %{ok,BackUrl} = application:get_env(up_back_url),
  %BackUrl.
  case application:get_env(up_back_url) of
    {ok, FrontUrl} -> FrontUrl;
    undefined -> "http://localhost:8888/pg/pay_succ_info"
  end.

mer_list() ->
%%  [<<"898350249000240">>, <<"898350249000242">>].
  {ok, UpMerList} = application:get_env(?APP, up_mer_list),
  proplists:get_value(gw_netbank, UpMerList) ++ proplists:get_value(gw_wap, UpMerList).

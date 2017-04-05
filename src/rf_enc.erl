%%%-------------------------------------------------------------------
%%% @author jiarj
%%% @copyright (C) 2017, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 31. 三月 2017 16:20
%%%-------------------------------------------------------------------
-module(rf_enc).
-author("jiarj").
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

-compile(export_all).


-behaviour(gen_server).

%% API
-export([start_link/0,
  public_key_file/2,
  private_key/2,
  sign/3,
  sign_fun/2,
  verify/4,
  sign_hex/3,
  sign_hex_fun/2,
  verify_hex/4,
  save_mcht_pk_file/2,
  reload_keys/0,
  perf_tc/0,

  save_mcht_req_pk_file_raw/2
]).

%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-define(SERVER, ?MODULE).
%%-define(MCHT_KEY_LOC, "/keys/mcht/").
-define(APP, payment_gateway).

-record(state, {mcht_keys}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec(start_link() ->
  {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

public_key_file(MchtId, Direction) ->
  gen_server:call(?SERVER, {public_key_file, MchtId, Direction}).

private_key(MchtId, Direction) ->
  gen_server:call(?SERVER, {private_key, MchtId, Direction}).

sign(MchtId, Direction, SignString) ->
  gen_server:call(?SERVER, {sign, MchtId, Direction, SignString}).

sign_fun(MchtId, Direction) ->
  gen_server:call(?SERVER, {sign_fun, MchtId, Direction}).

verify(MchtId, Direction, DigestBin, SignString) ->
  gen_server:call(?SERVER, {verify, MchtId, Direction, DigestBin, SignString}).

sign_hex(MchtId, Direction, SignString) ->
  gen_server:call(?SERVER, {sign_hex, MchtId, Direction, SignString}).

sign_hex_fun(MchtId, Direction) ->
  gen_server:call(?SERVER, {sign_hex_fun, MchtId, Direction}).

verify_hex(MchtId, Direction, DigestBin, SignString) when
  is_integer(MchtId),
  is_binary(DigestBin),
  is_binary(SignString),
  is_atom(Direction) ->
  gen_server:call(?SERVER, {verify_hex, MchtId, Direction, DigestBin, SignString}).

save_mcht_pk_file(MchtId, ReqPK) when
  is_integer(MchtId),
  is_binary(ReqPK) ->
  gen_server:call(?SERVER, {save_mcht_pk_file, MchtId, ReqPK, rsa_key}).

save_mcht_req_pk_file_raw(MchtId, ReqPK) when
  is_integer(MchtId),
  is_binary(ReqPK) ->
  gen_server:call(?SERVER, {save_mcht_pk_file, MchtId, ReqPK, raw}).

reload_keys() ->
  gen_server:call(?SERVER, {reload_keys}).


perf_tc() ->
  F = sign_fun(1, req),
  L = [$a || _X <- lists:seq(1, 300)],
  S = list_to_binary(L),
  %lager:info("ts=~p", [datetime_x_fin:now()]),
  %[ sign(1,req,<<"hello">>) || _X <- lists:seq(1,10000)],
  %lager:info("after sign, ts1=~p~n",[xfutils:now()]),
  %[ F(<<"hello">>) || _X <- lists:seq(1,10000)],
  perf(10000, F, S),
  %lager:info("after sign_fun, ts1=~p", [datetime_x_fin:now()]),
  ok.

perf(0, _, _) ->
  ok;
perf(N, F, S) ->
  F(S),
  perf(N - 1, F, S).


%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
-spec(init(Args :: term()) ->
  {ok, State :: #state{}} | {ok, State :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term()} | ignore).
init([]) ->
  %% 读取商户的相关秘钥
  Dict = load_mcht_keys(),
  {ok, #state{mcht_keys = Dict}}.

load_mcht_keys() ->
  %% 定位商户秘钥所在目录
  PrivDir = mcht_keys_dir(),

  %% 处理目录下所有的商户
  Keys = [mcht_all_keys([PrivDir, Dir], Dir) || Dir <- mcht_dirs(PrivDir), lists:nth(1, Dir) =/= $.],
  %lager:debug("~p", [Keys]),
  KeysDict = dict:from_list(lists:flatten(Keys)),
  KeysDict.


mcht_keys_dir() ->
%%  [xfutils:priv_dir(?APP), ?MCHT_KEY_LOC].
  rfe_utils_env:get_path([home, priv_dir, mcht_keys_dir]).




mcht_dirs(Dir) ->
  {ok, MchtDirList} = file:list_dir_all(Dir),
  MchtDirList.

mcht_all_keys(Dir, MchtId) ->
  %% req: private_key, public_key
  ReqKeys = mcht_one_keypair([Dir, "/req"]),
  %lager:debug("ReqKeys = ~p", [ReqKeys]),


  %% resp: private_key , public_key
  RespKeys = mcht_one_keypair([Dir, "/resp"]),

  lager:info("load mcht [~p] keys ok!", [MchtId]),

  [{{list_to_integer(MchtId), req}, ReqKeys}, {{list_to_integer(MchtId), resp}, RespKeys}].


digest(Bin) ->
  DigestBin = crypto:hash(sha, Bin),
  DigestHexUpper = xfutils:bin_to_hex(DigestBin),
  list_to_binary(string:to_lower(binary_to_list(DigestHexUpper))).


sign_internal(DigestBin, PrivateKey) ->
  Digest = digest(DigestBin),
  Signed = public_key:sign(Digest, sha, PrivateKey),
  Signed.
%base64:encode(Signed).
sign_internal_nodigest(DigestBin, PrivateKey) ->
  %Digest = digest(DigestBin),
  Digest = DigestBin,
  Signed = public_key:sign(Digest, sha, PrivateKey),
  Signed.

sign_hex(DigestBin, PrivateKey) ->
  SignedBin = sign_internal_nodigest(DigestBin, PrivateKey),
  Hex = xfutils:bin_to_hex(SignedBin),
  Hex.

sign64(DigestBin, PrivateKey) ->
  base64:encode(sign_internal(DigestBin, PrivateKey)).



verify_internal(DigestBin, Signature64, PublicKey) ->
  Digested = digest(DigestBin),
  Signature = base64:decode(Signature64),
  public_key:verify(Digested, sha, Signature, PublicKey).

verify_internal_nodigest(DigestBin, Signature64, PublicKey) ->
  %Digested = digest(DigestBin),
  Digested = DigestBin,
  Signature = base64:decode(Signature64),
  public_key:verify(Digested, sha, Signature, PublicKey).

verify_hex(DigestBin, SignatureHex, PublicKey) ->
  %Digested = digest(DigestBin),
  Digested = DigestBin,
  Signature = xfutils:hex_to_bin(SignatureHex),
  public_key:verify(Digested, sha, Signature, PublicKey).



mcht_one_keypair(Dir) ->
%% private_key
  PrivateKeyFileName = [Dir, "/private_key.pem"],
  %lager:debug("private key file = ~p", [PrivateKeyFileName]),
  PrivateKey = get_private_key(PrivateKeyFileName, ""),


%% public_key
  PublicKeyFileName = [Dir, "/public_key.pem"],
  %lager:debug("public key file = ~p", [PublicKeyFileName]),
  PublicKey = get_public_key(PublicKeyFileName),

  {PrivateKey, PublicKey}.



get_private_key(KeyFileName, Pwd) ->
  try
    {ok, PemBin} = file:read_file(KeyFileName),
    [RSAEntry | _Rest] = public_key:pem_decode(PemBin),
    RsaKeyInfo = public_key:pem_entry_decode(RSAEntry, Pwd),
    lager:info("private key = ~p~n", [RsaKeyInfo]),
    %lager:debug("private key = ~p", [RsaKeyInfo]),
    %RsaKey = public_key:der_decode('RSAPrivateKey', RsaKeyInfo#'PrivateKeyInfo'.privateKey),
    %RsaKey.
    {RsaKeyInfo, PemBin}

  catch
    error :X ->
      lager:error("read private key file ~p error! Msg = ~p", [KeyFileName, X]),
      {<<>>, <<>>}
  end.


get_public_key(KeyFileName) ->
  try
    {ok, PemBin} = file:read_file(KeyFileName),
    [Certificate] = public_key:pem_decode(PemBin),
    %{_, DerCert, _} = Certificate,
    %Decoded = public_key:pkix_decode_cert(DerCert, otp),
    %PublicKey = Decoded#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subjectPublicKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey,
    %PublicKey.
    PublicKey = public_key:pem_entry_decode(Certificate),
    %lager:info("public key = ~p~n", [PublicKey]),
    %lager:debug("public key = ~p", [PublicKey]),
    {PublicKey, PemBin}
  catch
    error:X ->
      lager:error("read public key file ~p error! Msg = ~p", [KeyFileName, X]),
      {<<>>, <<>>}

  end.

get_public_key_raw(KeyFileName) ->
  {ok, PemBin} = file:read_file(KeyFileName),
  {S1, L1} = binary:match(PemBin, <<"-----BEGIN PUBLIC KEY-----">>),
  <<_:S1/bytes, _:L1/bytes, Rest/binary>> = PemBin,
  lager:debug("Rest = ~p", [Rest]),
  {S2, _L2} = binary:match(Rest, <<"---">>),
  <<Raw:S2/bytes, _/binary>> = Rest,
  lager:debug("Raw = ~p", [Raw]),
  RawWOCR = binary:replace(Raw, <<"\n">>, <<>>, [global]),
  lager:debug("RawWOCR = ~p", [RawWOCR]),
  RespPKDecoded = base64:decode(RawWOCR),
  RespPKHex = xfutils:bin_to_hex(RespPKDecoded),
  lager:debug("RespPKHex = ~p", [RespPKHex]),

  RespPKHex.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_call(Request :: term(), From :: {pid(), Tag :: term()},
    State :: #state{}) ->
  {reply, Reply :: term(), NewState :: #state{}} |
  {reply, Reply :: term(), NewState :: #state{}, timeout() | hibernate} |
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), Reply :: term(), NewState :: #state{}} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_call({sign_hex, MchtId, Direction, DigestBin},
    _From, #state{mcht_keys = KeyDict} = State) ->
  %%{PrivateKey, _} = dict:fetch({MchtId, Direction}, KeyDict),
  PrivateKey = get_private_key_from_state(MchtId, Direction, KeyDict),
  %Signed64 = sign64(DigestBin, PrivateKey),
  SignedHex = sign_hex(DigestBin, PrivateKey),
  {reply, SignedHex, State};

handle_call({sign_hex_fun, MchtId, Direction},
    _From, #state{mcht_keys = KeyDict} = State) ->
  %%{PrivateKey, _} = dict:fetch({MchtId, Direction}, KeyDict),
  PrivateKey = get_private_key_from_state(MchtId, Direction, KeyDict),
  F = fun(DigestBin) ->
    %Signed64 = sign64(DigestBin, PrivateKey),
    %Signed64
    SignedHex = sign_hex(DigestBin, PrivateKey),
    SignedHex
      end,
  {reply, F, State};
handle_call({verify_hex, MchtId, Direction, DigestBin, Signature64},
    _From, #state{mcht_keys = KeyDict} = State) ->
  %%{_, PublicKey} = dict:fetch({MchtId, Direction}, KeyDict),
  PublicKey = get_public_key_from_state(MchtId, Direction, KeyDict),
  Verified = verify_hex(DigestBin, Signature64, PublicKey),
  {reply, Verified, State};

handle_call({sign, MchtId, Direction, DigestBin},
    _From, #state{mcht_keys = KeyDict} = State) ->
  %% {PrivateKey, _} = dict:fetch({MchtId, Direction}, KeyDict),
  PrivateKey = get_private_key_from_state(MchtId, Direction, KeyDict),
  Signed64 = sign64(DigestBin, PrivateKey),
  {reply, Signed64, State};

handle_call({sign_fun, MchtId, Direction},
    _From, #state{mcht_keys = KeyDict} = State) ->
  %%{PrivateKey, _} = dict:fetch({MchtId, Direction}, KeyDict),
  PrivateKey = get_private_key_from_state(MchtId, Direction, KeyDict),
  F = fun(DigestBin) ->
    Signed64 = sign64(DigestBin, PrivateKey),
    Signed64
      end,
  {reply, F, State};
handle_call({verify, MchtId, Direction, DigestBin, Signature64},
    _From, #state{mcht_keys = KeyDict} = State) ->
  %%{_, PublicKey} = dict:fetch({MchtId, Direction}, KeyDict),
  PublicKey = get_public_key_from_state(MchtId, Direction, KeyDict),
  Verified = verify_internal(DigestBin, Signature64, PublicKey),
  {reply, Verified, State};
handle_call({save_mcht_pk_file, MchtId, ReqPK, Option}, _From, State) when is_atom(Option) ->
  PrivDir = mcht_keys_dir(),
  StrMchtId = integer_to_binary(MchtId),
  %% copy from mcht 0
  %copy_keys_dir_from_mcht_0(MchtId, PrivDir), %%liunx
  copy_keys_dir_from_mcht_0_win(MchtId, PrivDir), %%windows


  %% write pk file
  %% trust-one platform send pk in "rsa public key" format , not erlang "public key" format
  write_mcht_req_pk(PrivDir, StrMchtId, ReqPK, Option),

  %% get resp public key
  %% get public key from pkcs#1 format pem file, not the one in pkcs#8 format one
  RespPemFileName = list_to_binary([PrivDir, "/", StrMchtId, "/resp/public_key.pem.pkcs1"]),
  lager:debug("RespPemFileName=~p", [RespPemFileName]),
  RespPK = rfe_utils_enc:get_public_key_raw_pkcs1(RespPemFileName),
  lager:debug("RespPK = ~p", [RespPK]),

  {reply, RespPK, State};

handle_call({reload_keys}, _From, _State) ->
  Dict = load_mcht_keys(),
  {reply, ok, #state{mcht_keys = Dict}};


handle_call({public_key_file, MchtId, Direction}, _From, #state{mcht_keys = KeyDict} = State) ->
  PublicKeyFile = get_public_key_file_from_state(MchtId, Direction, KeyDict),
  {reply, PublicKeyFile, State};


handle_call(_Request, _From, State) ->
  {reply, ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_cast(Request :: term(), State :: #state{}) ->
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_cast(_Request, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
-spec(handle_info(Info :: timeout() | term(), State :: #state{}) ->
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_info(_Info, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
-spec(terminate(Reason :: (normal | shutdown | {shutdown, term()} | term()),
    State :: #state{}) -> term()).
terminate(_Reason, _State) ->
  ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
-spec(code_change(OldVsn :: term() | {down, term()}, State :: #state{},
    Extra :: term()) ->
  {ok, NewState :: #state{}} | {error, Reason :: term()}).
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
get_private_key_from_state(MchtId, Direction, Dict)
  when is_integer(MchtId), is_atom(Direction),
  ((Direction =:= resp) or (Direction =:= req)) ->
  {{PrivateKey, _PrivateKeyFile}, _} = fetch_from_state({MchtId, Direction}, Dict),
  PrivateKey.

get_private_key_file_from_state(MchtId, Direction, Dict)
  when is_integer(MchtId), is_atom(Direction),
  ((Direction =:= resp) or (Direction =:= req)) ->
  {{_PrivateKey, PrivateKeyFile}, _} = fetch_from_state({MchtId, Direction}, Dict),
  PrivateKeyFile.

get_public_key_from_state(MchtId, Direction, Dict)
  when is_integer(MchtId), is_atom(Direction),
  ((Direction =:= resp) or (Direction =:= req)) ->
  {_, {PublicKey, _PublicKeyFile}} = fetch_from_state({MchtId, Direction}, Dict),
  PublicKey.

get_public_key_file_from_state(MchtId, Direction, Dict)
  when is_integer(MchtId), is_atom(Direction),
  ((Direction =:= resp) or (Direction =:= req)) ->
  {_, {_PublicKey, PublicKeyFile}} = fetch_from_state({MchtId, Direction}, Dict),
  PublicKeyFile.

fetch_from_state(Key, Dict) ->
  try
    dict:fetch(Key, Dict)
  catch
    _:_ ->
      lager:error("Could not find key in state. Key = ~p", [Key]),
      No = <<"no content">>,
      {{No, No}, {No, No}}
  end.

copy_keys_dir_from_mcht_0(MchtId, PrivDir) when is_integer(MchtId) ->
  StrMchtId = integer_to_binary(MchtId),
  Cmd = ["cd ", PrivDir, " ;",
    "rm -rf ", StrMchtId, " ;",
    "mkdir ", StrMchtId, ";",
    "cp -r 0/* ", StrMchtId
  ],
  Cmd1 = binary_to_list(list_to_binary(Cmd)),
  lager:debug("Cmd1= ~p", [Cmd1]),
  os:cmd(Cmd1).
copy_keys_dir_from_mcht_1(MchtId, PrivDir) when is_integer(MchtId) ->
  StrMchtId = integer_to_binary(MchtId),
  Cmd = ["cd ", PrivDir, " ;",
    "rm -rf ", StrMchtId, " ;",
    "mkdir ", StrMchtId, ";",
    "cp -r 1/* ", StrMchtId
  ],
  Cmd1 = binary_to_list(list_to_binary(Cmd)),
  lager:debug("Cmd1= ~p", [Cmd1]),
  os:cmd(Cmd1).

copy_keys_dir_from_mcht_0_win(MchtId, PrivDir) when is_integer(MchtId) ->

  StrMchtId = integer_to_binary(MchtId),
  GolaDir = binary_to_list(list_to_binary([PrivDir,StrMchtId])),
  lager:debug("Cmd1= ~p", [GolaDir]),
  case filelib:is_dir(GolaDir) of
      true -> filemanager:deleteDir(GolaDir);
      false-> []
  end,
  filemanager:copyDir(PrivDir++"0",GolaDir).

write_mcht_req_pk(PrivDir, StrMchtId, ReqPK, Option) ->
  ReqPKPemFileName = list_to_binary([PrivDir, "/", StrMchtId, "/req/public_key.pem"]),
  BinPemPK = case Option of
               rsa_key ->
                 xfutils:bin_to_pem_rsa(ReqPK);
               raw ->
                 ReqPK
             end,
  lager:debug("FileName=~p,BinPemPK = ~p", [ReqPKPemFileName, BinPemPK]),
  ok = file:write_file(ReqPKPemFileName, BinPemPK),
  lager:info("Write req pem file success !", []).

%%%===================================================================
init_test() ->
  rfe_utils_env:app_env_init_for_test(),
  init([]),
  ?assertEqual(1, 1).

mcht_dirs_test() ->
  rfe_utils_env:app_env_init_for_test(),
%%  MchtKeysDir = [xfutils:priv_dir(?APP), ?MCHT_KEY_LOC],
  %lager:info("~nMchtKeyDir = ~p~n",[MchtKeysDir]),
  MchtKeysDir = rfe_utils_env:get_path([home, priv_dir, mcht_keys_dir]),
  DirList = mcht_dirs(MchtKeysDir),
  ?assertEqual(true, lists:member("1", DirList)).

mcht_all_keys_test() ->
  rfe_utils_env:app_env_init_for_test(),
%%  L = mcht_all_keys([xfutils:priv_dir(?APP), ?MCHT_KEY_LOC, "1"], "1"),
  MchtKeysDir = rfe_utils_env:get_path([home, priv_dir, mcht_keys_dir]),
  L = mcht_all_keys([MchtKeysDir, "/1"], "1"),

  lager:info("all_keys = ~p", [L]),
  [{{1, req}, {{PrivateKey, _}, {PublicKey, _}}}, _] = L,
  String = <<"Hello world">>,

  % enc test
  Encrypted = public_key:encrypt_private(String, PrivateKey),
  Decrypted = public_key:decrypt_public(Encrypted, PublicKey),

  ?assertEqual(String, Decrypted),

  % sign/verify test
  DigestUpper = xfutils:bin_to_hex(crypto:hash(sha, String)),
  Digest = list_to_binary(string:to_lower(binary_to_list(DigestUpper))),
  Signed = public_key:sign(Digest, sha, PrivateKey),
  %lager:info("Signed = ~p~n,Digest = ~p", [Signed, Digest]),

  ?assertEqual(true, public_key:verify(Digest, sha, Signed, PublicKey)).

digest_test() ->
  A = <<"accNo=6225682141000002950&accessType=0&backUrl=https://101.231.204.80:5000/gateway/api/backTransReq.do&bizType=000201&certId=124876885185794726986301355951670452718&channelType=07&currencyCode=156&encoding=UTF-8&merId=898340183980105&orderId=2014110600007615&signMethod=01&txnAmt=000000010000&txnSubType=01&txnTime=20150109135921&txnType=01&version=5.0.0">>,

  ?assertEqual(digest(A), <<"c527432e8f632d555c651eaf8e5e0b027405fa46">>).

sign_test() ->
  rfe_utils_env:app_env_init_for_test(),
  Key = unionpay_config:privateKey(999),
  DigestBin = <<"accNo=6225682141000002950&accessType=0&backUrl=https://101.231.204.80:5000/gateway/api/backTransReq.do&bizType=000201&certId=124876885185794726986301355951670452718&channelType=07&currencyCode=156&encoding=UTF-8&merId=898340183980105&orderId=2014110600007615&signMethod=01&txnAmt=000000010000&txnSubType=01&txnTime=20150109135921&txnType=01&version=5.0.0">>,
  SignResult = sign64(DigestBin, Key),
  ?assertEqual(SignResult, <<"hLrvwNR5lHtQUKU/tXvwY857BKbKOQCGrKbLcg/68ZIG04yGnMFcmKUOO/cAt7SREoyjbOmSR6FUficTeofXZr7arrujbtyBB3wolmQ0BKTAVA7jjYaaYmMQxRkSlMElX7kYSsZyqCAzIzDkqKA36nN9w5g2wur3fbkha7GPyIw=">>),
  ok.

sign_hex_test() ->
  rfe_utils_env:app_env_init_for_test(),
  Key = unionpay_config:privateKey(999),
  DigestBin = <<"accNo=6225682141000002950&accessType=0&backUrl=https://101.231.204.80:5000/gateway/api/backTransReq.do&bizType=000201&certId=124876885185794726986301355951670452718&channelType=07&currencyCode=156&encoding=UTF-8&merId=898340183980105&orderId=2014110600007615&signMethod=01&txnAmt=000000010000&txnSubType=01&txnTime=20150109135921&txnType=01&version=5.0.0">>,
  SignResult = sign_hex(DigestBin, Key),
  ?assertEqual(SignResult, <<"751F180B6B5B1709B41AFB6C2C6C1FEC233D6C9541709E9186BE352B739E4BD5C371A3377046C3C4EFA8C881EE6AC5F70AEAA5F03597DD81BD2E9276AE2BC6C7552560B72B1EF0243F785577AF4885DE705FD3F43A1F38F74A4C0D371622546B9F43B6B563F00067C52807E4D40B9706F1B6E5C8483141226CF3BEC164BB3A98">>),

  ok.

verify_hex_test() ->
  rfe_utils_env:app_env_init_for_test(),
  Dict = load_mcht_keys(),
  %% {{Mcht1PrivateKey, _}, {Mcht1PublicKey, _}} = dict:fetch({1, req}, Dict),
  Mcht1PrivateKey = get_private_key_from_state(1, req, Dict),
  Mcht1PublicKey = get_public_key_from_state(1, req, Dict),
  Sign = <<"0000120160420201604202006143765380572006141{pI=test,aI=03429500040006212,aN=上海聚孚金融信息服务有限公司,aB=农业银行上海张江集电港支行}1003http://localhost:8888/pg/simu_mcht_back_succ_infohttp://localhost:8888/pg/simu_mcht_front_succ"/utf8>>,
  %Sig = <<"A5C0ECB6F4F40CE07DD6519521658F5DAD2136761FFB42F6CC475BD797824B21D2FEB1FE97AEC59963D84F31C84D1A0F20BB77E7C498954711084493635BBFB4B40BDC200327188DF1610A88082CEBF0F763ACCB942976F223C50488A80F644B6ADA41826DB448611DB6E7663011C168FE6B46444AEF21BB42F79240063FD6786AF3E490100DF6A70E11B6856F97B861BA99A9C6328A9C64D526733268D5C725A694EDC4142C2926FCEFB425FBA1D39B11EF7132DB80D6B6244894F25B8B3EFC3A862DED998F75187B2304E7DB56D2037215721EBDCC0528ED949A924359759B2E29CB78BAADE3771839D5F1460F82DBCC65F98FD8DC16EAD25482DD9A5EB069">>,
  Sig = sign_hex(Sign, Mcht1PrivateKey),
  R = verify_hex(Sign, Sig, Mcht1PublicKey),
  ?assertEqual(R, true).

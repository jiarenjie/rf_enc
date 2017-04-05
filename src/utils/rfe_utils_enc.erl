%%%-------------------------------------------------------------------
%%% @author simon
%%% @copyright (C) 2016, <COMPANY>
%%% @doc 秘钥、签名相关处理的接口
%%%
%%% @end
%%% Created : 05. Nov 2016 10:13 PM
%%%-------------------------------------------------------------------
-module(rfe_utils_enc).
-author("simon").

%% API
-export([
  public_key_validate/1
  , get_public_key_raw/1
  , get_public_key_raw_pkcs1/1
  , get_public_key/1
]).


%%-------------------------------------------------------------------
-spec public_key_validate(PK) -> ok when
  PK :: binary().

public_key_validate(PK) when is_binary(PK) ->
  lager:debug("Public key raw data is: ~p", [PK]),

  PemBin = xfutils:bin_to_pem_rsa(PK),

  lager:debug("PemBin = ~p", [PemBin]),

  [Certificate] = public_key:pem_decode(PemBin),

  PublicKey = public_key:pem_entry_decode(Certificate),

  lager:debug("PublicKey decoded from PemBin = ~p", [PublicKey]),

  ok.

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
    PublicKey
  catch
    error:X ->
      lager:error("read public key file ~p error! Msg = ~p", [KeyFileName, X]),
      <<>>

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

get_public_key_raw_pkcs1(KeyFileName) ->
  {ok, PemBin} = file:read_file(KeyFileName),
  {S1, L1} = binary:match(PemBin, <<"-----BEGIN RSA PUBLIC KEY-----">>),
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

%%%-------------------------------------------------------------------
%%% @author simon
%%% @copyright (C) 2016, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 22. Dec 2016 5:36 PM
%%%-------------------------------------------------------------------
-module(rfe_utils_env).
-include_lib("eunit/include/eunit.hrl").
-author("simon").

%% API
-export([get_path/1,
  get_path/2,
  get_filename/1,
  app_env_init_for_test/0
]).

app_env_init_for_test() ->
  App = payment_gateway,
  application:set_env(App, priv_dir, "/priv"),
  application:set_env(App, mcht_keys_dir, "/keys/mcht"),
  application:set_env(App, up_keys_dir, "/keys"),
  ok.


get_path(Env, trim) ->
  get_filename(Env).

get_path(home) ->
  {ok, Path} = init:get_argument(home),
  Path;
get_path(Env) when is_atom(Env) ->
  case application:get_env(Env) of
    undefined ->
      {ok, Path} = application:get_env(payment_gateway, Env),
      Path;
    {ok, Path} ->
      Path
  end;
get_path(EnvList) when is_list(EnvList) ->
  Path = [[get_path(Item), "/"] || Item <- EnvList],
  lists:flatten(Path).

get_filename(Env) ->
  Path = get_path(Env),
  droplast(Path, $/).

droplast(String, Char) when is_list(String), is_integer(Char) ->
  StringReverse = lists:reverse(String),

  TrimString = trim_head(StringReverse, Char),

  lists:reverse(TrimString).

trim_head([Char | Rest], Char) ->
  trim_head(Rest, Char);
trim_head(Rest, _Char) ->
  Rest.

get_file_test() ->
  ?assertEqual("/ab/c", droplast("/ab/c/", $/)),
  ?assertEqual("/ab/c", droplast("/ab/c", $/)),
  ok.

get_path_test() ->
  App = payment_gateway,
  application:set_env(App, test1, "/aaa/bbb"),
  application:set_env(App, test2, "/ccc/ddd"),
  application:set_env(App, file1, "filename"),
  application:set_env(App, file2, "filename2/"),

  ?assertEqual("/aaa/bbb", get_path(test1)),
  ?assertEqual("/ccc/ddd", get_path(test2)),
  ?assertEqual("filename", get_path(file1)),

  ?assertEqual("/aaa/bbb//ccc/ddd/", get_path([test1, test2])),
  ?assertEqual("/ccc/ddd//aaa/bbb/", get_path([test2, test1])),

  ?assertEqual("/aaa/bbb/filename2", get_filename([test1, file2])),

  ?assertEqual("/aaa/bbb//ccc/ddd", get_path([test1, test2], trim)),
  ?assertEqual("/ccc/ddd//aaa/bbb", get_path([test2, test1], trim)),

  ok.


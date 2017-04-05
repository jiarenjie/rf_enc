%%%-------------------------------------------------------------------
%% @doc rf_enc top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(rf_enc_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([]) ->
    io:format("init"),
    Rf_enc = {rf_enc,
        {rf_enc, start_link, []},
        permanent, 2000, worker, [rf_enc]},
    {ok, { {one_for_all, 4, 3600}, [Rf_enc]} }.

%%====================================================================
%% Internal functions
%%====================================================================

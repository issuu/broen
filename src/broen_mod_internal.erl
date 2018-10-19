%%% @hidden
-module(broen_mod_internal).

-include_lib("yaws/include/yaws_api.hrl").

-export([out/1]).
-export([init/2]).

out(Arg) ->
  broen_core:handle(Arg, <<"http_exchange_internal">>, broen_mod:default_cookie_path(Arg#arg.server_path),
                    []).

init(Req0, State) ->
  Ret = broen_core:handle_cowboy(Req0, <<"http_exchange_internal">>,
                                 broen_mod:default_cookie_path(cowboy_req:path(Req0)), []),
  {ok, Ret, State}.
%%% @hidden
-module(broen_mod_internal).

-export([init/2]).

init(Req0, State) ->
  Ret = broen_core:handle(Req0, <<"http_exchange_internal">>,
                                 broen_mod:default_cookie_path(cowboy_req:path(Req0)), []),
  {ok, Ret, State}.

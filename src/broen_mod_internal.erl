%%% @hidden
-module(broen_mod_internal).

-include_lib("yaws/include/yaws_api.hrl").

-export([out/1]).

out(Arg) ->
  broen_core:handle(Arg, <<"http_exchange_internal">>, broen_mod:default_cookie_path(Arg#arg.server_path),
                    []).

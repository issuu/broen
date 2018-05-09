-module(broen_mod).

-include_lib("yaws/include/yaws_api.hrl").

-export([out/1]).
-export([default_cookie_path/1]).

out(Arg) ->
  TimeBefore = os:timestamp(),
  Res = broen_core:handle(Arg, <<"http_exchange">>, default_cookie_path(Arg#arg.server_path), []),
  TimeAfter = os:timestamp(),
  lager:debug("broen_mod:out ~p", [timer:now_diff(TimeAfter, TimeBefore)]),
  Res.

-spec default_cookie_path(string()) -> binary().
default_cookie_path(ServerPath) ->
  %% Use first two path levels in cookies
  case string:tokens(ServerPath, "/") of
    [First, Second | _] -> list_to_binary(["/", First, "/", Second]);
    _ -> list_to_binary(ServerPath) % None or one level
  end.

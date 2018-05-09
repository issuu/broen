-module(broen_server_crash_handler).

-export([crashmsg/3]).

%% crashmsg/3 is called whenever the server decides to crash internally
crashmsg(_Arg, _ServerConf, Str) ->
  {_, _, Micro} = Now = erlang:timestamp(),
  Time = calendar:now_to_local_time(Now),
  Token = to_hex(crypto:hash(sha256, term_to_binary({Time, Micro, Str}))),
  PrettyString = iolist_to_binary(re:replace(Str, "\n\s*", "", [global])),
  ok = lager:error("Crash: ~p", [[{token, Token}, {msg, PrettyString}]]),
  {ehtml,
   [{h2, [], "Internal error, thin-layer code crashed"},
    {br},
    {hr},
    {pre, [], Token},
    {hr}]}.

to_hex(X) -> to_hex(X, []).

to_hex(<<>>, Acc) -> lists:reverse(Acc);
to_hex(<<C1:4, C2:4, Rest/binary>>, Acc) ->
  to_hex(Rest, [hexdigit(C2), hexdigit(C1) | Acc]).

hexdigit(C) when C >= 0, C =< 9 -> C + $0;
hexdigit(C) when C =< 15        -> C + $a - 10.

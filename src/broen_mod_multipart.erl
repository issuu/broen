%%% @hidden
-module(broen_mod_multipart).

-include_lib("yaws/include/yaws_api.hrl").

-define(MULTIPART_BODY_LIMIT, 10 * 1024 * 1024).  % 10MB

-record(multipart_state, {parts = [], total_size = 0, last_chunk = false}).
-record(part, {name = "", opts = [], body = []}).

-export([out/1]).

out(#arg{req = #http_request{method = 'POST'}, headers = #headers{content_type = "multipart/form-data" ++ _}, state = State} = Arg) ->
  State1 = case State of undefined -> #multipart_state{}; V -> V end,
  post_multipart(Arg, State1);
out(#arg{req = #http_request{method = M}, headers = #headers{content_type = CType}}) ->
  % wrong request
  lager:debug("Wrong request - method: ~p, content-type: ~p", [M, CType]),
  folsom_metrics:notify({'broen_mod_multipart.failure.400', 1}),
  err().

%% Private
err() ->
  [{status, 400},
   {content, "text/plain", "Bad request"}].

post_multipart(Arg, State) ->
  case yaws_api:parse_multipart_post(Arg) of
    {cont, Cont, Res} ->
      case accumulate(Arg, Res, State) of
        {done, Result} ->
          call_broen(Arg, Result);
        {cont, #multipart_state{total_size = S}} when S > ?MULTIPART_BODY_LIMIT ->
          lager:debug("Size of multipart exceeds limit - size so far: ~p (bytes)", [S]),
          folsom_metrics:notify({'broen_mod_multipart.failure.400', 1}),
          err();
        {cont, NewState} ->
          {get_more, Cont, NewState}
      end;
    {result, Res} ->
      % handle result
      case accumulate(Arg, Res, State#multipart_state{last_chunk = true}) of
        {done, Result} ->
          call_broen(Arg, Result);
        {cont, _} ->
          err()
      end;
    {error, Reason} ->
      lager:warning("Failed to parse multipart data: ~p", [Reason]),
      err()
  end.

call_broen(Arg, Result) ->
  % send through thin layer
  broen_core:handle(Arg#arg{state = {multipart, Result}, clidata = undefined}, <<"http_exchange">>, broen_mod:default_cookie_path(Arg#arg.server_path),
                    []).

% we are done, since we received result from parse_multipart
accumulate(_Arg, [], #multipart_state{last_chunk = true} = State) ->
  {done, state_to_result(State)};
% need more data from the client
accumulate(_Arg, [], State) -> {cont, State};
% begin of a new part
accumulate(Arg, [{head, {Name, Opts}} | Rest], State) ->
  NewState = new_part(State, Name, Opts),
  accumulate(Arg, Rest, NewState);
% partial/full body
accumulate(Arg, [{Token, Data} | Rest], State) when Token == part_body orelse Token == body ->
  NewState = accum_body(State, list_to_binary(Data)),
  accumulate(Arg, Rest, NewState).

state_to_result(#multipart_state{parts = Parts}) ->
  {[part_to_broen_format(Part) || Part <- Parts]}.

part_to_broen_format(#part{name = N, opts = O, body = B}) ->
  {N, {[{<<"opts">>, {O}},
        {<<"body">>, iolist_to_binary(lists:reverse(B))}]}}.

accum_body(#multipart_state{total_size = Size,
                            parts      = [#part{body = B} = Cur | Parts]} = State,
           NewPartBody) ->
  NewSize = Size + byte_size(NewPartBody),
  State#multipart_state{total_size = NewSize, parts = [Cur#part{body = [NewPartBody | B]} | Parts]}.

new_part(#multipart_state{parts = Parts} = S, Name, Opts) ->
  S#multipart_state{parts = [#part{name = list_to_binary(Name),
                                   opts = part_options(Opts)} | Parts]}.

part_options([])                   -> [];
part_options([{"name", _} | Rest]) -> part_options(Rest);  % skip name
part_options([{K, V} | Rest]) when is_atom(K) ->
  part_options([{atom_to_list(K), V} | Rest]);
part_options([{K, V} | Rest]) when is_list(K) andalso is_list(V) ->
  [{list_to_binary(K), list_to_binary(V)} | part_options(Rest)].

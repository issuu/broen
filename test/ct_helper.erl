-module(ct_helper).

-export([all_tests/1]).

%%
%% Private functions
%%
is_test_case({F, A}) when is_atom(F), A == 1 ->
    case atom_to_list(F) of
        "test_" ++ _ ->
            true;
        _ ->
            false
    end;
is_test_case(_) ->
    false.

%%
%% Public functions
%%

%% Returns a list of all exported functions named test_...
-spec all_tests(module()) -> [atom()].
all_tests(Module) ->
    [ F || FunArity = {F, 1} <- proplists:get_value(exports, Module:module_info()),
           is_test_case(FunArity) == true ].

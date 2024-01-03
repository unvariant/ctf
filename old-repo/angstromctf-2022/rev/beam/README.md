# Beam
This was more of an osint problem than a rev problem. My team spent a few hours looking up how to run/decompile elixir beam files and came up with nothing. I finally came across a [website](https://medium.com/learn-elixir/disassemble-elixir-code-1bca5fe15dd1) that had an article about decompiling beam files. I first installed `iex` and ran
```elixir
f = './Elixir.Angstrom.CLI.beam'
result = :beam_lib.chunks(f,[:abstract_code])
{:ok,{_,[{:abstract_code,{_,ac}}]}} = result
IO.puts :erl_prettypr.format(:erl_syntax.form_list(ac))
```
which outputted
```elixir
-file("lib/angstrom.ex", 1).

-module('Elixir.Angstrom.CLI').

-compile([no_auto_import]).

-export(['__info__'/1, check/0, main/0, main/1]).

-spec '__info__'(attributes |
                 compile |
                 functions |
                 macros |
                 md5 |
                 exports_md5 |
                 module | 
                 deprecated) -> any().

'__info__'(module) -> 'Elixir.Angstrom.CLI';
'__info__'(functions) ->
    [{check, 0}, {main, 0}, {main, 1}];
'__info__'(macros) -> [];
'__info__'(exports_md5) ->
    <<"lc\203Aò©a5e\233\213\002\225\216ú\002">>;
'__info__'(Key = attributes) ->
    erlang:get_module_info('Elixir.Angstrom.CLI', Key);
'__info__'(Key = compile) ->
    erlang:get_module_info('Elixir.Angstrom.CLI', Key);
'__info__'(Key = md5) ->
    erlang:get_module_info('Elixir.Angstrom.CLI', Key);
'__info__'(deprecated) -> [].

check() ->
    _input@1 =
        'Elixir.Enum':map('Elixir.String':to_charlist(get_input()),
                          fun (_x@1) -> _x@1 + 1 end),
    case _input@1 of
        [103, 106, 115, 102, 120, 112, 115, 108, 116] ->
            get_flag();
        _ -> 'Elixir.IO':puts(<<"Sorry, no flag for you">>)
    end.

get_flag() ->
    'Elixir.IO':puts('Elixir.File':'read!'(<<"flag.txt">>)).

get_input() ->
    'Elixir.String':trim('Elixir.IO':gets(<<"Password: ">>)).

main() -> main([]).

main(_args@1) -> check().
```
With this output you can see that the program is adding one to every input char and comparing it to an array. Subtracting one from every byte in the array and converting back to ascii yields `fireworks`.
```
> nc challs.actf.co 31400
Password: fireworks
actf{elixir_is_awesome}
```
## Flag: actf{elixir_is_awesome}
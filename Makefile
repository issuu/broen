REBAR=rebar3


### Local building
##################################
build:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

distclean: clean
	rm -rf _build

### Local testing
##################################
test: test-eunit test-ct

test-eunit:
	$(REBAR) eunit

test-ct:
	$(REBAR) ct --sys_config=test/sys-test.config

dialyzer:
	$(REBAR) dialyzer

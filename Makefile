REBAR=rebar3
CONFIG_FILE ?= test/sys-test.config


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
	$(REBAR) ct --readable=false --sys_config=$(CONFIG_FILE)
dialyzer:
	$(REBAR) dialyzer

publish:
	$(REBAR) hex publish

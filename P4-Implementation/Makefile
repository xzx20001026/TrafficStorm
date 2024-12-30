compile:
	sudo -E ${SDE_INSTALL}/bin/bf-p4c --target tofino -g --arch tna -o /opt/tstorm traffic_gen.p4
	sudo -E cp /opt/tstorm/traffic_gen.conf ${SDE_INSTALL}/share/p4/targets/tofino/tstorm.conf

start:
	sudo -E ${SDE}/run_switchd.sh -p tstorm

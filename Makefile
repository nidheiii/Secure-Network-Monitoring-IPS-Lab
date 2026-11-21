.PHONY: ids ips down demo measure benign logs
ids:      ; docker compose up -d --build && echo "Console: http://localhost:8080"
ips:      ; docker compose -f docker-compose.yml -f docker-compose.ips.yml up -d --build --force-recreate && echo "Console: http://localhost:8080 (IPS mode)"
down:     ; docker compose -f docker-compose.yml -f docker-compose.ips.yml down
logs:     ; docker compose logs -f suricata
measure:  ; python3 tools/attack_and_measure.py --runs 5
benign:   ; sh tools/benign_traffic.sh
# No Docker needed: console + simulated Suricata alerts at http://localhost:8080
demo:
	@mkdir -p /tmp/ipslab && : > /tmp/ipslab/eve.json
	@python3 tools/simulate_eve.py --out /tmp/ipslab/eve.json & \
	 EVE_PATH=/tmp/ipslab/eve.json python3 dashboard/server.py

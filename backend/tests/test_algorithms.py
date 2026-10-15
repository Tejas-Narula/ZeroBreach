
from network import create_demo_network
from algorithms import find_reachable_devices


def test_reachability_from_laptop():
    graph = create_demo_network()

    reachable = find_reachable_devices(graph, "laptop_1")

    assert reachable == {
        "laptop_1",
        "web_1",
        "app_1",
        "db_1",
        "backup_1",
    }


def test_blocked_connection():
    graph = create_demo_network()
    graph["web_1"]["app_1"]["allowed"] = False

    reachable = find_reachable_devices(graph, "laptop_1")

    assert reachable == {"laptop_1", "web_1"}

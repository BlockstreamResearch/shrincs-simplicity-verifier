import subprocess

def grind():
    for i in range(4000000000):
        with open("examples/shrincs/shrincs_main.wit", "w") as f:
            f.write(f"""{{
        "UXMSS_PROOF": {{
            "type": "(u256, u128, u128, (u128, (u32, [u128; 64]), List<u128, 512>), u32)",
            "value": "(0, 0, 0, (0, ({i}, [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]), list![0]), 0)"
        }}
}}""")
        a = subprocess.run(['make', 'shrincs_example'])
        if a.returncode == 0:
            print(f"Found ctr: {i}")
            break


grind()
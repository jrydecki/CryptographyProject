#!/usr/bin/python3
import subprocess
import json
import platform
import argparse


def get_sys_info():
    out = {}
    out["OS"] = platform.system()
    out["Machine"] = platform.machine()
    
    if out["OS"] == "Windows":
        out["Processor"] = platform.processor()

    elif out["OS"] == "Darwin":
        os.environ['PATH'] = os.environ['PATH'] + os.pathsep + '/usr/sbin'
        command ="sysctl -n machdep.cpu.brand_string"
        out["Processor"] = subprocess.check_output(command).strip()

    elif out["OS"] == "Linux":
        with open("/proc/cpuinfo", "r") as f:
            for line in f.readlines():
                line = line.strip()
                if line.startswith("model name"):
                    out["Processor"] = line.split(":", 1)[1].strip()

    return out

def process_output(raw_stdout):
    out = {}

    lines = raw_stdout.split("\n")
    num_lines = len(lines)
    i = 0

    while i < num_lines:
        line = lines[i]

        if line.startswith("OpenSSL"):
            library = "OpenSSL"
            tmp = {
                "Library": library,
                "CBC": {},
                "OFB": {},
                "CTR": {},
            }

            tmp["CBC"]["Encryption (ms)"] = float(lines[i+2].strip().split(" ", 2)[1])
            tmp["CBC"]["Decryption (ms)"] = float(lines[i+3].strip().split(" ", 2)[1])
            tmp["OFB"]["Encryption (ms)"] = float(lines[i+5].strip().split(" ", 2)[1])
            tmp["OFB"]["Decryption (ms)"] = float(lines[i+6].strip().split(" ", 2)[1])
            tmp["CTR"]["Encryption (ms)"] = float(lines[i+8].strip().split(" ", 2)[1])
            tmp["CTR"]["Decryption (ms)"] = float(lines[i+9].strip().split(" ", 2)[1])
            out[library] = tmp
            i += 9

        elif line.startswith("Custom Modes"):
            library = "Custom"
            tmp = {
                "Library": library,
                "CBC": {},
                "OFB": {},
                "CTR": {},
            }

            tmp["CBC"]["Encryption (ms)"] = float(lines[i+2].strip().split(" ", 2)[1])
            tmp["CBC"]["Decryption (ms)"] = float(lines[i+3].strip().split(" ", 2)[1])
            tmp["OFB"]["Encryption (ms)"] = float(lines[i+5].strip().split(" ", 2)[1])
            tmp["OFB"]["Decryption (ms)"] = float(lines[i+6].strip().split(" ", 2)[1])
            tmp["CTR"]["Encryption (ms)"] = float(lines[i+8].strip().split(" ", 2)[1])
            tmp["CTR"]["Decryption (ms)"] = float(lines[i+9].strip().split(" ", 2)[1])
            out[library] = tmp
            i += 9


        i += 1
        
    return(out)


def setup_stats_dict():
    stats = {
        "AES": {
            "OpenSSL": {
                "CBC": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "OFB": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "CTR": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
            },
            "Custom": {
                "CBC": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "OFB": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "CTR": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
            },
        },
        "DES": {
            "OpenSSL": {
                "CBC": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "OFB": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "CTR": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
            },
            "Custom": {
                "CBC": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "OFB": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "CTR": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
            },
        },
        "3DES": {
            "OpenSSL": {
                "CBC": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "OFB": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "CTR": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
            },
            "Custom": {
                "CBC": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "OFB": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
                "CTR": {
                    "Average Encryption Time (ms)": 0.0,
                    "Average Decryption Time (ms)": 0.0,
                },
            },
        },
    }

    return stats


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--runs", required=True, help="The number of times to run the tests.")
    args = parser.parse_args()

    RUNS = int(args.runs) 
    cmd_aes = ['./test_aes']
    cmd_des = ['./test_des']
    cmd_3des = ['./test_3des']
    

    results = {}
    results["SYSTEM INFO"] = get_sys_info()
    results["RUNS"] = []

    # Run Tests
    for run in range(RUNS):

        tmp = {}
        tmp["RUN"] = run
        
        out = subprocess.run(cmd_aes, capture_output=True, text=True)
        out_dict = process_output(out.stdout)
        tmp["AES"] = out_dict

        out = subprocess.run(cmd_des, capture_output=True, text=True)
        out_dict = process_output(out.stdout)
        tmp["DES"] = out_dict

        out = subprocess.run(cmd_3des, capture_output=True, text=True)
        out_dict = process_output(out.stdout)
        tmp["3DES"] = out_dict

        results["RUNS"].append(tmp)
        

    # Calcluate Stats
    stats = setup_stats_dict()

    # Add Values
    for run_dict in results["RUNS"]:
        aes = run_dict["AES"]
        des = run_dict["DES"]
        des3 = run_dict["3DES"]

        # AES
        stats["AES"]["OpenSSL"]["CBC"]["Average Encryption Time (ms)"] += aes["OpenSSL"]["CBC"]["Encryption (ms)"]
        stats["AES"]["OpenSSL"]["CBC"]["Average Decryption Time (ms)"] += aes["OpenSSL"]["CBC"]["Decryption (ms)"]
        stats["AES"]["OpenSSL"]["OFB"]["Average Encryption Time (ms)"] += aes["OpenSSL"]["OFB"]["Encryption (ms)"]
        stats["AES"]["OpenSSL"]["OFB"]["Average Decryption Time (ms)"] += aes["OpenSSL"]["OFB"]["Decryption (ms)"]
        stats["AES"]["OpenSSL"]["CTR"]["Average Encryption Time (ms)"] += aes["OpenSSL"]["CTR"]["Encryption (ms)"]
        stats["AES"]["OpenSSL"]["CTR"]["Average Decryption Time (ms)"] += aes["OpenSSL"]["CTR"]["Decryption (ms)"]
        stats["AES"]["Custom"]["CBC"]["Average Encryption Time (ms)"] += aes["Custom"]["CBC"]["Encryption (ms)"]
        stats["AES"]["Custom"]["CBC"]["Average Decryption Time (ms)"] += aes["Custom"]["CBC"]["Decryption (ms)"]
        stats["AES"]["Custom"]["OFB"]["Average Encryption Time (ms)"] += aes["Custom"]["OFB"]["Encryption (ms)"]
        stats["AES"]["Custom"]["OFB"]["Average Decryption Time (ms)"] += aes["Custom"]["OFB"]["Decryption (ms)"]
        stats["AES"]["Custom"]["CTR"]["Average Encryption Time (ms)"] += aes["Custom"]["CTR"]["Encryption (ms)"]
        stats["AES"]["Custom"]["CTR"]["Average Decryption Time (ms)"] += aes["Custom"]["CTR"]["Decryption (ms)"]

        # DES
        stats["DES"]["OpenSSL"]["CBC"]["Average Encryption Time (ms)"] += des["OpenSSL"]["CBC"]["Encryption (ms)"]
        stats["DES"]["OpenSSL"]["CBC"]["Average Decryption Time (ms)"] += des["OpenSSL"]["CBC"]["Decryption (ms)"]
        stats["DES"]["OpenSSL"]["OFB"]["Average Encryption Time (ms)"] += des["OpenSSL"]["OFB"]["Encryption (ms)"]
        stats["DES"]["OpenSSL"]["OFB"]["Average Decryption Time (ms)"] += des["OpenSSL"]["OFB"]["Decryption (ms)"]
        stats["DES"]["OpenSSL"]["CTR"]["Average Encryption Time (ms)"] += des["OpenSSL"]["CTR"]["Encryption (ms)"]
        stats["DES"]["OpenSSL"]["CTR"]["Average Decryption Time (ms)"] += des["OpenSSL"]["CTR"]["Decryption (ms)"]
        stats["DES"]["Custom"]["CBC"]["Average Encryption Time (ms)"] += des["Custom"]["CBC"]["Encryption (ms)"]
        stats["DES"]["Custom"]["CBC"]["Average Decryption Time (ms)"] += des["Custom"]["CBC"]["Decryption (ms)"]
        stats["DES"]["Custom"]["OFB"]["Average Encryption Time (ms)"] += des["Custom"]["OFB"]["Encryption (ms)"]
        stats["DES"]["Custom"]["OFB"]["Average Decryption Time (ms)"] += des["Custom"]["OFB"]["Decryption (ms)"]
        stats["DES"]["Custom"]["CTR"]["Average Encryption Time (ms)"] += des["Custom"]["CTR"]["Encryption (ms)"]
        stats["DES"]["Custom"]["CTR"]["Average Decryption Time (ms)"] += des["Custom"]["CTR"]["Decryption (ms)"]

        # 3DES
        stats["3DES"]["OpenSSL"]["CBC"]["Average Encryption Time (ms)"] += des3["OpenSSL"]["CBC"]["Encryption (ms)"]
        stats["3DES"]["OpenSSL"]["CBC"]["Average Decryption Time (ms)"] += des3["OpenSSL"]["CBC"]["Decryption (ms)"]
        stats["3DES"]["OpenSSL"]["OFB"]["Average Encryption Time (ms)"] += des3["OpenSSL"]["OFB"]["Encryption (ms)"]
        stats["3DES"]["OpenSSL"]["OFB"]["Average Decryption Time (ms)"] += des3["OpenSSL"]["OFB"]["Decryption (ms)"]
        stats["3DES"]["OpenSSL"]["CTR"]["Average Encryption Time (ms)"] += des3["OpenSSL"]["CTR"]["Encryption (ms)"]
        stats["3DES"]["OpenSSL"]["CTR"]["Average Decryption Time (ms)"] += des3["OpenSSL"]["CTR"]["Decryption (ms)"]
        stats["3DES"]["Custom"]["CBC"]["Average Encryption Time (ms)"] += des3["Custom"]["CBC"]["Encryption (ms)"]
        stats["3DES"]["Custom"]["CBC"]["Average Decryption Time (ms)"] += des3["Custom"]["CBC"]["Decryption (ms)"]
        stats["3DES"]["Custom"]["OFB"]["Average Encryption Time (ms)"] += des3["Custom"]["OFB"]["Encryption (ms)"]
        stats["3DES"]["Custom"]["OFB"]["Average Decryption Time (ms)"] += des3["Custom"]["OFB"]["Decryption (ms)"]
        stats["3DES"]["Custom"]["CTR"]["Average Encryption Time (ms)"] += des3["Custom"]["CTR"]["Encryption (ms)"]
        stats["3DES"]["Custom"]["CTR"]["Average Decryption Time (ms)"] += des3["Custom"]["CTR"]["Decryption (ms)"]

        # Divide Values
        if (run_dict["RUN"] == (RUNS - 1)):
            stats["AES"]["OpenSSL"]["CBC"]["Average Encryption Time (ms)"] /= RUNS
            stats["AES"]["OpenSSL"]["CBC"]["Average Decryption Time (ms)"] /= RUNS
            stats["AES"]["OpenSSL"]["OFB"]["Average Encryption Time (ms)"] /= RUNS
            stats["AES"]["OpenSSL"]["OFB"]["Average Decryption Time (ms)"] /= RUNS
            stats["AES"]["OpenSSL"]["CTR"]["Average Encryption Time (ms)"] /= RUNS
            stats["AES"]["OpenSSL"]["CTR"]["Average Decryption Time (ms)"] /= RUNS
            stats["AES"]["Custom"]["CBC"]["Average Encryption Time (ms)"] /= RUNS
            stats["AES"]["Custom"]["CBC"]["Average Decryption Time (ms)"] /= RUNS
            stats["AES"]["Custom"]["OFB"]["Average Encryption Time (ms)"] /= RUNS
            stats["AES"]["Custom"]["OFB"]["Average Decryption Time (ms)"] /= RUNS
            stats["AES"]["Custom"]["CTR"]["Average Encryption Time (ms)"] /= RUNS
            stats["AES"]["Custom"]["CTR"]["Average Decryption Time (ms)"] /= RUNS
            stats["DES"]["OpenSSL"]["CBC"]["Average Encryption Time (ms)"] /= RUNS
            stats["DES"]["OpenSSL"]["CBC"]["Average Decryption Time (ms)"] /= RUNS
            stats["DES"]["OpenSSL"]["OFB"]["Average Encryption Time (ms)"] /= RUNS
            stats["DES"]["OpenSSL"]["OFB"]["Average Decryption Time (ms)"]/= RUNS
            stats["DES"]["OpenSSL"]["CTR"]["Average Encryption Time (ms)"] /= RUNS
            stats["DES"]["OpenSSL"]["CTR"]["Average Decryption Time (ms)"] /= RUNS
            stats["DES"]["Custom"]["CBC"]["Average Encryption Time (ms)"]/= RUNS
            stats["DES"]["Custom"]["CBC"]["Average Decryption Time (ms)"] /= RUNS
            stats["DES"]["Custom"]["OFB"]["Average Encryption Time (ms)"] /= RUNS
            stats["DES"]["Custom"]["OFB"]["Average Decryption Time (ms)"] /= RUNS
            stats["DES"]["Custom"]["CTR"]["Average Encryption Time (ms)"] /= RUNS
            stats["DES"]["Custom"]["CTR"]["Average Decryption Time (ms)"] /= RUNS
            stats["3DES"]["OpenSSL"]["CBC"]["Average Encryption Time (ms)"] /= RUNS
            stats["3DES"]["OpenSSL"]["CBC"]["Average Decryption Time (ms)"] /= RUNS
            stats["3DES"]["OpenSSL"]["OFB"]["Average Encryption Time (ms)"] /= RUNS
            stats["3DES"]["OpenSSL"]["OFB"]["Average Decryption Time (ms)"] /= RUNS
            stats["3DES"]["OpenSSL"]["CTR"]["Average Encryption Time (ms)"]/= RUNS
            stats["3DES"]["OpenSSL"]["CTR"]["Average Decryption Time (ms)"]/= RUNS
            stats["3DES"]["Custom"]["CBC"]["Average Encryption Time (ms)"] /= RUNS
            stats["3DES"]["Custom"]["CBC"]["Average Decryption Time (ms)"] /= RUNS
            stats["3DES"]["Custom"]["OFB"]["Average Encryption Time (ms)"] /= RUNS
            stats["3DES"]["Custom"]["OFB"]["Average Decryption Time (ms)"] /= RUNS
            stats["3DES"]["Custom"]["CTR"]["Average Encryption Time (ms)"] /= RUNS
            stats["3DES"]["Custom"]["CTR"]["Average Decryption Time (ms)"] /= RUNS
    



    results["STATISTICS"] = stats

    with open("out.json", "w") as f:
        f.write(json.dumps(results, indent=3))

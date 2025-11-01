# tool to help identify http services\sites available on any port. 
# it is handy as the output is csv file easy to grep or filter in Excel. 
# you can use NMAP scripts, but they give too much uneusefull information if you wand just to find if scecific host\port runs http service.
#!/bin/bash

max_http_body_length=40  # Максимальная длина http_body

# Help
function show_help() {
    echo "Usage: $0 [-f <host_file>] [-o <output_file>] [-p <ports>]"
    echo "Options:"
    echo "  -f <host_file>      Specify the file with hostnames (required)"
    echo "  -o <output_file>    Specify the output file (required)"
    echo "  -p <ports>          Specify the ports (required, e.g., '80,443')"
    echo "Example: $0 -f hosts.txt -o output.csv -p 80,443"
    exit 1
}

# Command-line arguments processing
while getopts "f:o:p:h" opt; do
    case $opt in
        f)
            host_file="$OPTARG"
            ;;
        o)
            output_file="$OPTARG"
            ;;
        p)
            ports="$OPTARG"
            ;;
        h)
            show_help
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            show_help
            ;;
    esac
done

# Check for required parameters
if [ -z "$host_file" ] || [ -z "$output_file" ] || [ -z "$ports" ]; then
    echo "Required options: -f, -o, -p" >&2
    show_help
fi

# Remove the output file if it exists
rm -f "$output_file"

# Output CSV headers
echo "Hostname;Port;Protocol;HTTP Code;HTTP Size;Redirect Location;HTTP Body" >> "$output_file"

# Loop through hostnames from the file
while read -r hostname; do
    IFS=',' read -ra port_array <<< "$ports"
    for port in "${port_array[@]}"; do
        http_response=$(curl -sI -m 10 "http://${hostname}:${port}")
        http_code=$(echo "$http_response" | grep -oP 'HTTP/\d\.\d \K\d+')
        http_location=$(echo "$http_response" | grep -i 'Location' | sed -e 's/Location: //I' -e 's/\r//')
        if [ -n "$http_code" ]; then
            http_size=$(echo -n "$http_response" | wc -c)
            http_body=$(curl -s -m 10 "http://${hostname}:${port}" | head -c $max_http_body_length | tr -d '\r\n')

            https_response=$(curl -sI -m 10 "https://${hostname}:${port}")
            if [ $? -eq 0 ]; then
                https_code=$(echo "$https_response" | grep -oP 'HTTP/\d\.\d \K\d+')
                https_location=$(echo "$https_response" | grep -i 'Location' | sed -e 's/Location: //I' -e 's/\r//')
                if [ -n "$https_code" ]; then
                    https_size=$(echo -n "$https_response" | wc -c)
                    https_body=$(curl -s -m 10 "https://${hostname}:${port}" | head -c $max_http_body_length | tr -d '\r\n')
                    echo "${hostname};${port};HTTPS;${https_code};${https_size};${https_location};${https_body}" >> "$output_file"
                fi
            fi

            echo "${hostname};${port};HTTP;${http_code};${http_size};${http_location};${http_body}" >> "$output_file"

            # Display on the screen
            echo "${hostname} ; ${port} ; HTTP ; ${http_code} ; ${http_size} ; ${http_location}; ${http_body}"
            if [ $? -eq 0 ]; then
                echo "${hostname} ; ${port} ; HTTPS ; ${https_code} ; ${https_size} ; ${https_location}; ${https_body}"
            fi
        fi
    done
done < "$host_file"

echo "Results are saved to $output_file"

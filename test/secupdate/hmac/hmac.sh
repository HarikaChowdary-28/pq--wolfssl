#!/bin/bash

# Loop 1000 times
for ((i=1; i<=1000; i++))
do    
    # Run your executable here and save files to the created directory
    cat "output/output_$i.txt" "hmac_tags/hmac_tag_$i.txt" > "msgs/msg_$i.txt"
    
    # Optionally, you can add a sleep command if you want to introduce a delay between each run
    # sleep 1
done


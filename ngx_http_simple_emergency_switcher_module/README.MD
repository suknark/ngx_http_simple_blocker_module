## Simple module to switch traffic from broken upstream to another one



## Example

```
emergency_switch on;                    #set module on
emergency_switch_to "upstream_name";    #name of emergency upstream
emergency_switch_errors 4xx;            #type of tagret error
emergency_switch_percent 90;            #percent of target error
```



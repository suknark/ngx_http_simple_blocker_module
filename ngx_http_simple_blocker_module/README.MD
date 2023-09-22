## Simple module for exclude or pass traffic by user-agent or cookie in request



## Example

```
blocker_set "user_agent" "ex" "MyApp\/[1-5]"; # do not pass requests by user-agent matched regex
blocker_set "cookie" "in" "passMe"; # pass traffic just with cookie
```

## Settings

```
blocker_set "user_agent|cookie" "ex(exclude)|in(incliude)" "patern_to_match";
```



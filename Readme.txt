
"Function String Associate" 
An IDA Pro 5.xx plug-in that automatically comments functions by strings 
it has inside it.
By Sirmabus  V: 1.0B

From the chaos of a 10,000+ functions et al, this plug-in is to help
reverse by extracting various "assert"(1), etc. strings, making some sense 
of them and adding them as a function comment. 
As you browse around, at a glance the comment might show a bit what the
functions purpose is.

Works best (of course) for targets that have a lot of string references in
them.  Some will have many, some will have none.

<(1) http://en.wikipedia.org/wiki/Assert>


[Install]
Copy the plug-in to your IDA Pro 5.xx "plugins" directory. 
Edit your "plugins.cfg" with a hotkey to run it, etc.
See the IDA docs for more help on this.

Example:
"FunctionStringAssociate IDA_FunctionStringAssociate_PlugIn.plw Alt-6 0"


[How to run it]
Just invoke it using your selected IDA hot-key or from "Edit->Plugins".


[How it works]
Iterates every function, for each function iterates elements looking for
strings. Then sorts, these strings, etc., with some assumption about 
relevance.

   
-Sirmabus


Terms of Use
------------
This software is provided "as is", without any guarantee made as to its
suitability, or fitness for any particular use. It may contain bugs, so use
this software is at your own risk.  The author takes no responsibly for 
any damage that might be caused through its use.   
   

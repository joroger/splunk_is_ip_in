from os import path, chdir
chdir( path.dirname( 
       path.abspath(__file__) 
    ) )


import xml.etree.ElementTree as ET
tree = ET.parse('./test.xml')
root = tree.getroot()

print( root.find("{http://www.w3.org/2005/Atom}content") )
for x in root:
    for child in x:
        print( child.tag )
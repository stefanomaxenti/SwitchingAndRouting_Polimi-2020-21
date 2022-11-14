"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
	"Simple topology example."

	def __init__( self ):
		"Create custom topo."

        # Initialize topology
		Topo.__init__( self )

        # Add hosts and switches
		h1 = self.addHost( 'h1' )
		h2 = self.addHost( 'h2' )
		h3 = self.addHost( 'h3' )
		h4 = self.addHost( 'h4' )
		h5 = self.addHost( 'h5' )
		h6 = self.addHost( 'h6' )
		h7 = self.addHost( 'h7' )
                h8 = self.addHost( 'h8' )
                h9 = self.addHost( 'h9' )
                h10 = self.addHost( 'h10' )
                h11 = self.addHost( 'h11' )
                h12 = self.addHost( 'h12' )
		h13 = self.addHost( 'h13' )
                h14 = self.addHost( 'h14' )
                h15 = self.addHost( 'h15' )
                h16 = self.addHost( 'h16' )
                h17 = self.addHost( 'h17' )
                h18 = self.addHost( 'h18' )		
		s1 = self.addSwitch( 's1' )
		s2 = self.addSwitch( 's2' )
		s3 = self.addSwitch( 's3' )
		s4 = self.addSwitch( 's4' )
		s5 = self.addSwitch( 's5' )
		s6 = self.addSwitch( 's6' )
		s7 = self.addSwitch( 's7' )
                s8 = self.addSwitch( 's8' )
                s9 = self.addSwitch( 's9' )
                s10 = self.addSwitch( 's10' )
                s11 = self.addSwitch( 's11' )
                s12 = self.addSwitch( 's12' )
		s13 = self.addSwitch( 's13' )
                s14 = self.addSwitch( 's14' )
                s15 = self.addSwitch( 's15' )
                s16 = self.addSwitch( 's16' )
                s17 = self.addSwitch( 's17' )
                s18 = self.addSwitch( 's18' )
        # Add links
		self.addLink( h1, s1 )
		self.addLink( h2, s2 )
		self.addLink( h3, s3 )
		self.addLink( h4, s4 )
		self.addLink( h5, s5 )
		self.addLink( h6, s6 )
		self.addLink( h7, s7 )
                self.addLink( h8, s8 )
                self.addLink( h9, s9 )
                self.addLink( h10, s10 )
                self.addLink( h11, s11 )
                self.addLink( h12, s12 )
		self.addLink( h13, s13 )
                self.addLink( h14, s14 )
                self.addLink( h15, s15 )
                self.addLink( h16, s16 )
                self.addLink( h17, s17 )
                self.addLink( h18, s18 )
		self.addLink( s1, s2 )
		self.addLink( s2, s3 )
		self.addLink( s3, s4 )
		self.addLink( s4, s5 )
		self.addLink( s5, s6 )
		self.addLink( s6, s7 )
		self.addLink( s7, s8 )
		self.addLink( s8, s9 )
		self.addLink( s9, s10 )
		self.addLink( s10, s11 )
		self.addLink( s11, s12 )
		self.addLink( s12, s13 )
		self.addLink( s13, s14 )
		self.addLink( s14, s15 )
		self.addLink( s15, s16 )
		self.addLink( s16, s17 )
		self.addLink( s17, s18 )
		self.addLink( s18, s1 )



topos = { 'mytopo': ( lambda: MyTopo() ) }

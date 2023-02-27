# SFMC Auth

This system authenticates users to the SFMC system, and allows users to connect their local minecraft client to sfmc.siliconvortex.com via SSH tunnel.

# Client
On startup, a keypair will be created.  The user is then authenticated via Discord, and sends the OIDC code, along with public key, to sfmcsigner.siliconvortex.com to get a short-lived, signed certificate.

Once signed, this client opens an SSH connection to sfmcssh.siliconvortex.com and port-forwards localhost:2345 to the remote host.

The user can now connect to localhost:2345 to play minecraft, over the ssh tunnel.

# SFMC Signer Server

## Signer Listener
Listens to requests to sign key.
Verifies OIDC code and gets user's attributes.
If user is on allow list, server signs key, and returns signed key.

## Discord Bot
This bot provides an interface to manage user allow list.
Allow list is controlled via Discord bot.

# SFMC SSH Server
Listens for authorized ssh client (via signed key), and allows port-forward to minecraft instance.


# TODO

1. config story
9. tests
4. port-forward localhost:2345 (mc port) to through ssh tunnel
5. restrict ports to forward
6. dns name sfmc.siliconvortex.com -> localhost
7. stream all responses -> json.Decoder
8. benchmarks

# StreamIdentify

Some prototype code to explore the feasability of detecting ABR video streams within a capture, even if the streams are over https.

## Basic Concepts

Takes advantage of the fact that an ABR stream will be made up of a repeating sequence of "(<Request><Response>)+ <silence>".
The requests are expected to be tiny HTTP requests, were as the responses will be of content ranging from 10s Kbps for audio streams, 
up to many Mbps video stream files.

Once the clients buffer is full it is expected that the client will fetch streams at approximately the same rate as the segment durations.
If the client downloads faster than real-time then the intervals between the end of each client quiet period will be regular and match 
the content duration.

## Operation
./StreamIdentify -f samples/bunny-dash-5Mbps-4s.cap

Processes the file identified and by default outputs summary of any connections identified as being possible streams.
The output summary provides estimation of the download bitrate and the predicted nominal bitrate of the media content.
If accurate this could be used to condition the transfer stream or predict when bandwith will be required for the connection.

Other options are available to increase the verbosity of the output or modify algorithm parameters. These are described with --help.

## Implementation
As a basic proof of concept this uses a simple algorithm with thresholds to identify the ABR streams based on identified bitrates and durations.
Further exploration of more advanced algorithms is warrented to identify the optimum way to do this. This could include more statistical
methods such as looking at percentiles or running averages, or an ai model could be used to identify streams based on machine learning of
the models.

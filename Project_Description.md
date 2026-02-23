# Segulah Niggun database

## Definitions
* _Niggun_ - a melodic tune
* _Niggunim_ - the plural of _niggun_.

## Purpose

This is a web app that will provide to the public a database of _niggunim_.

## End user experience

End users should be able to browse the database by searching for the song name or description or by he following categories:
* Key
* Tempo
* Singer
* Author

When browsing, app should display the list of _niggunim_. When clicking on a specific niggun, it should open a card that lets the user see all the information and listen to the song.

## Administrator experience

Administrator should sign in with a username password.
Administrator should be able to do the following:
* Add and remove users
* Add and remove database entries

### Adding database entries
* Be able to upload music file (any file supported by modern web browsers)
* Enter the following fields
  * Audio file (either upload or provide URL - if proviing URL, fetch the file and store server-side)
  * Singer (required)
  * Title (required)
  * Tempo (optional)
  * Author (required)
  * Key (optional)
  * Notes (optional)
  * Date uploaded (automatically logged)

## Server details
This will be hosted on an Ubuntu server.  We can install whatever we need on the server.

## Questions from the robot

What stack do you want (frontend, backend, database) - please choose what you think is best.

Should the public site be fully open (no login), with only admin behind authentication? - yes public site fully open.

For admin auth, do you want a single admin role or multiple roles/permissions? - single admin role

You mention searching by “description,” but the entry fields list “Notes.” Are those the same field? - yes these are the same

Should Singer and Author allow multiple values per niggun, or just one each? - allow multiple vales

For Tempo and Key, do you want free text or standardized values (e.g., BPM + musical key list)? - standardized values.  Tempo - "Fast, medium, slow". Key - musical key list.

For audio uploads/URLs, do you want file size/type limits and virus/scanning checks? - yes let's say 20MB upload limit.  Limit file type to known audio formats that play on modern browsers.

Where should audio files be stored on Ubuntu (local filesystem path, or do you want object storage compatibility)? - stored in file system

Should entries/users be hard-deleted or soft-deleted (recoverable)? - hard delete fine.

Do you want an MVP first (core CRUD + search + playback), then enhancements after? - es MVP first.
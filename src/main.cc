/**
 * @file main.cc
 *
 * Copyright (c) 2011-2023 Cloudware S.A. All rights reserved.
 *
 * This file is part of casper-inotify.
 *
 * casper-inotify is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * casper-inotify is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with casper. If not, see <http://www.gnu.org/licenses/>.
 */

#include "api.h"
#include "version.h"

#include <syslog.h>
#include <signal.h> // sigemptyset, sigaction, etc...
#include <string.h> // strsignal, etc...

void on_signal (int a_sig_no)
{
    const char* const name = strsignal(a_sig_no);
    fprintf(stdout, "on_signal: %s\n", name);
}


int main( int argc, char **argv ) 
{
    
    // TODO: log rotate signal
    // struct sigaction act;

    // memset(&act, 0, sizeof(act));

    // sigemptyset(&act.sa_mask);
    // act.sa_handler = on_signal;
    // act.sa_flags    = SA_NODEFER;
    // if ( -1 == sigaction(SIGTTIN, &act, 0) ) {
    //     fprintf(stderr, "%d - %s\n", errno, strerror(errno));
    //     fflush(stderr);
    //     return -1;
    // }
    
    casper::inotify::API* api = new casper::inotify::API(CASPER_INOTIFY_ABBR, CASPER_INOTIFY_INFO);
    
    int rv;
    
    openlog(CASPER_INOTIFY_ABBR, (LOG_CONS | LOG_PID), LOG_CRON);
    syslog(LOG_NOTICE, "starting service (version %s)", CASPER_INOTIFY_INFO);
    
    try {
        api->Init(casper::inotify::API::LogLevel::_Event, "/var/log/" CASPER_INOTIFY_NAME "/events.log");
        api->Load("/etc/" CASPER_INOTIFY_NAME "/conf.json");
        rv = api->Watch();
        api->Unload();
    } catch (const casper::inotify::Exception& a_n_e) {
        rv = -1;
        syslog(LOG_ERR, "%s\n", a_n_e.what());
        api->Unload();
    } catch (const std::exception& a_e) {
        rv = -1;
        syslog(LOG_ERR, "%s\n", a_e.what());
        api->Unload();
    }

    delete api;
    
    syslog(LOG_NOTICE, "stopping service");
    closelog();
    
    return rv;
}

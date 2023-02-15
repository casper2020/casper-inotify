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
#include <assert.h>

static casper::inotify::API* g_api_ = nullptr;

void on_signal (int a_sig_no)
{
    assert(nullptr != g_api_);    
    g_api_->OnSignal(a_sig_no);
}

int main( int argc, char **argv ) 
{
    int rv = -1;

    // ... install signal handler for logrotate ...
    {
        struct sigaction act;
        memset(&act, 0, sizeof(act));
        sigemptyset(&act.sa_mask);
        act.sa_handler = on_signal;
        act.sa_flags   = SA_RESTART;
        if ( -1 == sigaction(SIGUSR1, &act, 0) ) {
            fprintf(stderr, "%d - %s\n", errno, strerror(errno));
            fflush(stderr);
            return rv;
        }
    }
    // ... open syslog ...
    openlog(CASPER_INOTIFY_NAME, (LOG_CONS | LOG_PID), LOG_CRON);
    syslog(LOG_NOTICE, "Starting (version %s)", CASPER_INOTIFY_INFO);
    // ... run ...
    g_api_ = new casper::inotify::API();
    try {
        g_api_->Init(casper::inotify::API::LogLevel::_Event, "/var/log/" CASPER_INOTIFY_NAME "/events.log");
        g_api_->Load("/etc/" CASPER_INOTIFY_NAME "/conf.json");
        rv = g_api_->Watch();
        g_api_->Unload();
    } catch (const casper::inotify::Exception& a_n_e) {
        rv = -1;
        syslog(LOG_ERR, "%s\n", a_n_e.what());
        g_api_->Unload();
    } catch (const std::exception& a_e) {
        rv = -1;
        syslog(LOG_ERR, "%s\n", a_e.what());
        g_api_->Unload();
    }
    delete g_api_;
    // ... close syslog ...
    syslog(LOG_NOTICE, "Stopping...");
    closelog();
    // ... done ...
    return rv;
}

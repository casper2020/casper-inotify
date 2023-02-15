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

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

static casper::inotify::API* g_api_ = nullptr;

void on_signal (int a_sig_no)
{
    assert(nullptr != g_api_);    
    g_api_->OnSignal(a_sig_no);
}

#define VAR_RUN_DIR "/var/run/" CASPER_INOTIFY_NAME
#define VAR_LOG_DIR "/var/log/" CASPER_INOTIFY_NAME
#define ETC_DIR "/etc/" CASPER_INOTIFY_NAME

int main( int argc, char **argv ) 
{
    int rv = -1;

    // ... ensure required directories ...
    {
        const mode_t mode = ( S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH );

        const char* const paths [2] = { VAR_RUN_DIR, VAR_LOG_DIR };
        for ( size_t idx = 0 ; idx < 2 ; ++idx  ) {
            if ( -1 == mkdir(paths[idx], mode) ) {
                if ( errno != EEXIST ) {
                    fprintf(stderr, "Unable to create directory '%s': %s!", paths[idx], strerror(errno));
                    fflush(stderr);
                    return rv;
                }
            }
        }
    }

    // ... install signal handler for logrotate ...
    {
        struct sigaction act;
        memset(&act, 0, sizeof(act));
        sigemptyset(&act.sa_mask);
        act.sa_handler = on_signal;
        act.sa_flags   = SA_RESTART;
        const std::vector<int> signals = { SIGUSR1, SIGQUIT, SIGTERM };
        for ( auto signal : signals ) {
            if ( -1 == sigaction(signal, &act, 0) ) {
                fprintf(stderr, "Unable to install signal handler: %d - %s\n", errno, strerror(errno));
                fflush(stderr);
                return rv;
            }
        }
    }
    // ... write pid file ...
    const char* const pid_file_uri = VAR_RUN_DIR "/" CASPER_INOTIFY_NAME ".pid";
    {
        FILE* file = fopen(pid_file_uri, "w");
        if ( nullptr == file ) {
            fprintf(stderr, "Unable to open pid file '%s': %d - %s\n", pid_file_uri, errno, strerror(errno));
            fflush(stderr);
            return rv;
        }
        const int bytes_written = fprintf(file, "%d", getpid());
        if ( bytes_written <= 0 ) {
            fclose(file);
            fprintf(stderr, "Unable to write date at pid file '%s'!", pid_file_uri);
            fflush(stderr);
            return rv;
        }
        fclose(file);
    }
    // ... open syslog ...
    openlog(CASPER_INOTIFY_NAME, (LOG_CONS | LOG_PID), LOG_CRON);
    syslog(LOG_NOTICE, "Starting (version %s)", CASPER_INOTIFY_INFO);
    syslog(LOG_NOTICE, "PID file is %s", pid_file_uri);
    // ... run ...
    g_api_ = new casper::inotify::API();
    try {
        g_api_->Init(casper::inotify::API::LogLevel::_Event, VAR_LOG_DIR "/" "events.log");
        g_api_->Load(ETC_DIR "/" "conf.json");
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
    // ... pid file ...
    if ( -1 != unlink(pid_file_uri) ) {
        if ( EINTR != errno ) {
            rv = -1;
            fprintf(stderr, "Unable to remove pid file '%s': %d - %s\n", pid_file_uri, errno, strerror(errno));
            fflush(stderr);
        }
    }
    // ... close syslog ...
    syslog(LOG_NOTICE, "Gone...");
    closelog();
    // ... done ...
    return rv;
}

use NativeCall;

class IO::Socket::SSL {
    has $.socket;
    has $.session;
    has $.xcred;

    my $library_init = False;

    sub gnutls_global_init() is native('libgnutls.so.28') { * }

    sub ssl_init(OpaquePointer, OpaquePointer, Callable, Callable, Callable) is native('lib') { * }
    sub ssl_recv(OpaquePointer, CArray[int8], int32) is native('lib') { * }
    sub ssl_send(OpaquePointer, CArray[int8], int32) is native('lib') { * }
    sub ssl_shutdown(OpaquePointer, OpaquePointer) is native('lib') { * }

    method new() {
        # needs mutex
        if !$library_init {
            $library_init = True;
            gnutls_global_init();
        }
        ####

        my $xcred = OpaquePointer;
        my $session = OpaquePointer;
        ssl_init($session, $xcred,
                 -> { $.socket.send(...) },
                 -> { $.socket.recv(...) },
                 -> { $.socket.??? });

    }

    method recv {
        ssl_recv($.session, ...);
    }

    method send {
        ssl_send($.session, ...);
    }

    method close {
        ssl_shutdown($.session, $.xcred);
        $.socket.close;
    }
}

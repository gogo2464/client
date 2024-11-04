# Author: Hubert Kario, (c) 2015-2022
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange


from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        GroupName, ExtensionType
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import SIG_ALL, AutoEmptyExtension


version = 9


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (\"sanity\" tests are always executed)")
    print(" -d             negotiate (EC)DHE instead of RSA key exchange, send")
    print("                additional extensions, usually used for (EC)DHE ciphers")
    print(" -C ciph        Use specified ciphersuite. Either numerical value or")
    print("                IETF name.")
    print(" -M | --ems     Advertise support for Extended Master Secret")
    print(" --help         this message")
    # already used single-letter options:
    # -m test-large-hello.py - min extension number for fuzz testing
    # -s signature algorithms sent by server
    # -k client key
    # -c client certificate
    # -z don't expect 1/n-1 record split in TLS1.0
    # -a override for expected alert description
    # -l override the expected alert level
    # -C explicit cipher for connection
    # -T expected certificates types in CertificateRequest
    # -b server is expected to have multiple (both) certificate types available
    #    at the same time
    # -t timeout to wait for messages (also count of NSTs in
    #    test-tls13-count-tickets.py)
    # -r perform renegotation multiple times
    # -S signature algorithms sent by client
    # -E additional extensions to be sent by client
    #
    # reserved:
    # -x expected fail for probe (alternative to -e)
    # -X expected failure message for probe (to be used together with -x)
    # -i enables timing the test using the specified interface
    # -o output directory for files related to collection of timing information


def main():
    host = "44fd86288430d3b355.gradio.live"
    port = 443
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    dhe = False
    ciphers = None
    ems = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:dC:M", ["help", "ems"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-x':
            expected_failures[arg] = None
            last_exp_tmp = str(arg)
        elif opt == '-X':
            if not last_exp_tmp:
                raise ValueError("-x has to be specified before -X")
            expected_failures[last_exp_tmp] = str(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '-d':
            dhe = True
        elif opt == '-C':
            if arg[:2] == '0x':
                ciphers = [int(arg, 16)]
            else:
                try:
                    ciphers = [getattr(CipherSuite, arg)]
                except AttributeError:
                    ciphers = [int(arg)]
        elif opt == '-M' or opt == '--ems':
            ems = True
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    if ciphers:
        if not dhe:
            # by default send minimal set of extensions, but allow user
            # to override it
            dhe = ciphers[0] in CipherSuite.ecdhAllSuites or \
                    ciphers[0] in CipherSuite.dhAllSuites
    else:
        if dhe:
            ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
        else:
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]




    # no canary currently at this moment

    conversations = {}


    for i in range(26):
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        if dhe:
            groups = [GroupName.secp256r1,
                      GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(SIG_ALL)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIG_ALL)
        if not ext:
            ext = None
        node = node.add_child(ClientHelloGenerator(
            ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
            extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"POST / HTTP/1.0\r\n\r\nusername=openai&password=isCloseAi\r\n\r\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["sanity"] = conversation

    # run the conversation
    good = 0
    bad = 0
    xfail = 0
    xpass = 0
    failed = []
    xpassed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    if run_only:
        if num_limit > len(run_only):
            num_limit = len(run_only)
        regular_tests = [(k, v) for k, v in conversations.items() if k in run_only]
    else:
        regular_tests = [(k, v) for k, v in conversations.items() if
                         (k != 'sanity') and k not in run_exclude]
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

    for c_name, c_test in ordered_tests:
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        exception = None
        try:
            runner.run()
        except Exception as exp:
            exception = exp
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if c_name in expected_failures:
            if res:
                xpass += 1
                xpassed.append(c_name)
                print("XPASS-expected failure but test passed\n")
            else:
                if expected_failures[c_name] is not None and  \
                    expected_failures[c_name] not in str(exception):
                        bad += 1
                        failed.append(c_name)
                        print("Expected error message: {0}\n"
                            .format(expected_failures[c_name]))
                else:
                    xfail += 1
                    print("OK-expected failure\n")
        else:
            if res:
                good += 1
                print("OK\n")
            else:
                bad += 1
                failed.append(c_name)

    print("Basic conversation script; check basic communication with typical")
    print("cipher, TLS 1.2 or earlier and RSA key exchange (or (EC)DHE if")
    print("-d option is used)\n")

    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(len(sampled_tests) + 2*len(sanity_tests)))
    print("SKIP: {0}".format(len(run_exclude.intersection(conversations.keys()))))
    print("PASS: {0}".format(good))
    print("XFAIL: {0}".format(xfail))
    print("FAIL: {0}".format(bad))
    print("XPASS: {0}".format(xpass))
    print(20 * '=')
    sort = sorted(xpassed ,key=natural_sort_keys)
    if len(sort):
        print("XPASSED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))
    sort = sorted(failed, key=natural_sort_keys)
    if len(sort):
        print("FAILED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))

    if bad or xpass:
        sys.exit(1)
        
    elif timing:
        if TimingRunner.check_tcpdump():
            tests = [('generic', None)]

            timing_runner = TimingRunner("{0}_v{1}".format(
                                            sys.argv[0],
                                            version),
                                         tests,
                                         outdir,
                                         host,
                                         port,
                                         interface,
                                         affinity,
                                         skip_extract=True,
                                         no_quickack=no_quickack)
            print("Pre-generating pre-master secret values...")
            with open(
                os.path.join(timing_runner.out_dir, 'data_values.bin'),
                "wb"
            ) as data_file:
                # create a real order of tests to run
                log = Log(os.path.join(timing_runner.out_dir, "real_log.csv"))
                actual_tests = []
                node_dict = {}
                for c_name, c_test in sampled_tests:
                    if run_only and c_name not in run_only or \
                            c_name in run_exclude:
                        continue
                    if not c_name.startswith("sanity"):
                        actual_tests.append(c_name)
                        node_dict[c_name] = generators[c_name]

                log.start_log(actual_tests)
                for _ in range(repetitions):
                    log.shuffle_new_run()
                log.write()
                log.read_log()
                test_classes = log.get_classes()
                queries = chain(repeat(0, WARM_UP), log.iterate_log())

                # generate the PMS values
                for executed, index in enumerate(queries):
                    g_name = test_classes[index]
                    g_node = node_dict[g_name]

                    res = g_node
                    assert len(res.data) == byte_len, \
                        len(res.data)

                    data_file.write(res.data)

            # fake the set of tests to run so it's just one
            data_file = open(
                os.path.join(timing_runner.out_dir, 'data_values.bin'),
                "rb"
            )

            conversation = Connect(host, port)
            node = conversation
            node = node.add_child(RawSocketWriteGenerator(
                data_file=data_file,
                data_length=byte_len
            ))
            node = node.add_child(ExpectAlert())
            node.add_child(ExpectClose())

            tests[:] = [('generic', conversation)]

            print("Running timing tests...")
            timing_runner.generate_log(
                ['generic'], [],
                repetitions * len(actual_tests))
            ret_val = timing_runner.run()
            if ret_val != 0:
                print("run failed")
                sys.exit(ret_val)
            os.remove(os.path.join(timing_runner.out_dir, 'log.csv'))
            os.rename(
                os.path.join(timing_runner.out_dir, 'real_log.csv'),
                os.path.join(timing_runner.out_dir, 'log.csv')
            )
            print("starting extraction")
            if not timing_runner.extract(fin_as_resp=no_alert):
                print("extract")
                ret_val = 2
            else:
                print("analysis")
                ret_val = timing_runner.analyse()

            if ret_val == 0:
                print("No statistically significant difference detected")
            elif ret_val == 1:
                print("Statistically significant difference detected")
            else:
                print("Statistical analysis exited with {0}".format(ret_val))
            sys.exit(ret_val)
        else:
            print("Could not run timing tests because tcpdump is not present!")
            sys.exit(1)
        print(20 * '=')
    

if __name__ == "__main__":
    main()

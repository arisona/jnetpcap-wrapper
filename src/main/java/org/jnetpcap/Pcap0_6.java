/*
 * Apache License, Version 2.0
 * 
 * Copyright 2013-2022 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 *   
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jnetpcap;

import java.lang.foreign.MemoryAddress;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;

import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.internal.PcapForeignDowncall;
import org.jnetpcap.internal.PcapForeignInitializer;

/**
 * Provides Pcap API method calls for up to libpcap version 0.6
 * 
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 *
 */
public sealed class Pcap0_6 extends Pcap0_5 permits Pcap0_7 {

	/**
	 * @see {@code pcap_t *pcap_open_dead(int linktype, int snaplen)}
	 * @since libpcap 0.6
	 */
	private final static PcapForeignDowncall pcap_open_dead;

	/**
	 * @see {@code void pcap_freecode(struct bpf_program *)}
	 * @since libpcap 0.6
	 */
	private static final PcapForeignDowncall pcap_freecode;

	static {
		try (var foreign = new PcapForeignInitializer(Pcap0_6.class)) {
			pcap_open_dead = foreign.downcall("pcap_open_dead(II)A");
			pcap_freecode = foreign.downcall("pcap_freecode(A)V");
		}
	}

	/**
	 * Free a BPF program.
	 * 
	 * <p>
	 * pcap_freecode() is used to free up allocated memory pointed to by a
	 * bpf_program struct generated by pcap_compile(3PCAP) when that BPF program is
	 * no longer needed, for example after it has been made the filter program for a
	 * pcap structure by a call to pcap_setfilter(3PCAP).
	 * </p>
	 *
	 * @param bpf_program_ptr memory address, a C pointer to BPF program
	 * @since libpcap 0.6
	 */
	static void freecode(MemoryAddress bpf_program_ptr) {
		Pcap0_6.pcap_freecode.invokeVoid(bpf_program_ptr.address());
	}

	/**
	 * Checks if the {@code Pcap} subclass at a specific <em>libpcap API
	 * version</em> is natively supported. This is a safe method to use anytime on
	 * any platform, weather native library is present or not.
	 * 
	 * <p>
	 * For example, {@code Pcap1_0.isSupported()} will accurately ascertain if
	 * libpcap API version 1.0 level calls are supported by the system runtime. Also
	 * a call such as {@code WinPcap.isSupported()} will determine if WinPcap
	 * related calls, ie. native WinPcap 4.1.3 or less, are supported and by
	 * extension if this is a Microsoft Windows platform.
	 * </p>
	 * <p>
	 * Due to <em>libpcap API versioning</em>, it is safe to assume that if
	 * {@code Pcap1_10.isSupported()} returns {@code true}, that at least
	 * <em>libpcap</em> API version 1.0 is installed on this platform, and that all
	 * lower version calls such as libpcap 0.8 and 0.9 are available as well. The
	 * subclass hierarchy of jNetPcap module reflects the versioning of libpcap and
	 * its derivatives and the public releases of the native libraries. For example
	 * {@code Npcap} class extends {@code WinPcap} class because <em>Npcap</em>
	 * project took over the support for <em>WinPcap</em> where it left off.
	 * </p>
	 * <p>
	 * Implementation notes: The check is performed by verifying that certain,
	 * subclass specific native symbols were linked with {@code Pcap} full which was
	 * introduced at a specific libpcap or related API levels.
	 * </p>
	 *
	 * @return true, if pcap is supported up to this specific version level,
	 *         otherwise false
	 * @see LibraryPolicy#setDefault(LibraryPolicy)
	 */
	public static boolean isSupported() {
		return pcap_open_dead.isNativeSymbolResolved();
	}

	/**
	 * Open a fake pcap_t for compiling filters or opening a capture for output.
	 * 
	 * <p>
	 * {@link #openDead} and pcap_open_dead_with_tstamp_precision() are used for
	 * creating a pcap_t structure to use when calling the other functions in
	 * libpcap. It is typically used when just using libpcap for compiling BPF full;
	 * it can also be used if using pcap_dump_open(3PCAP), pcap_dump(3PCAP), and
	 * pcap_dump_close(3PCAP) to write a savefile if there is no pcap_t that
	 * supplies the packets to be written.
	 * </p>
	 * 
	 * <p>
	 * When pcap_open_dead_with_tstamp_precision(), is used to create a pcap_t for
	 * use with pcap_dump_open(), precision specifies the time stamp precision for
	 * packets; PCAP_TSTAMP_PRECISION_MICRO should be specified if the packets to be
	 * written have time stamps in seconds and microseconds, and
	 * PCAP_TSTAMP_PRECISION_NANO should be specified if the packets to be written
	 * have time stamps in seconds and nanoseconds. Its value does not affect
	 * pcap_compile(3PCAP).
	 * </p>
	 *
	 * @param <T>      the generic pcap to instantiate and return
	 * @param factory  the pcap supplier
	 * @param linktype specifies the link-layer type for the pcap handle
	 * @param snaplen  specifies the snapshot length for the pcap handle
	 * @return A dead pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.6
	 */
	protected static <T extends Pcap> T openDead(BiFunction<MemoryAddress, String, T> factory, PcapDlt linktype,
			int snaplen)
			throws PcapException {
		MemoryAddress pcapPointer = pcap_open_dead.invokeObj(linktype.getAsInt(), snaplen);

		return factory.apply(pcapPointer, "dead:dlt=%s".formatted(linktype));
	}

	/**
	 * Open a device for capturing.
	 * 
	 * <p>
	 * {@code openLive} is used to obtain a packet capture handle to look at packets
	 * on the network. device is a string that specifies the network device to open;
	 * on Linux systems with 2.2 or later kernels, a device argument of "any" or
	 * NULL can be used to capture packets from all interfaces.
	 * </p>
	 *
	 * @param device  the device name
	 * @param snaplen specifies the snapshot length to be set on the handle
	 * @param promisc specifies whether the interface is to be put into promiscuous
	 *                mode. If promisc is non-zero, promiscuous mode will be set,
	 *                otherwise it will not be set
	 * @param timeout the packet buffer timeout, as a non-negative value, in units
	 * @param unit    time timeout unit
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static Pcap0_6 openLive(String device,
			int snaplen,
			boolean promisc,
			long timeout,
			TimeUnit unit) throws PcapException {

		return Pcap0_4.openLive(Pcap0_6::new, device, snaplen, promisc, timeout, unit);
	}

	/**
	 * Open a saved capture file for reading.
	 * 
	 * <p>
	 * pcap_open_offline() and pcap_open_offline_with_tstamp_precision() are called
	 * to open a ``savefile'' for reading.
	 * </p>
	 *
	 * @param fname specifies the name of the file to open. The file can have the
	 *              pcap file format as described in pcap-savefile(5), which is the
	 *              file format used by, among other programs, tcpdump(1) and
	 *              tcpslice(1), or can have the pcapng file format, although not
	 *              all pcapng files can be read
	 * @return the pcap handle
	 * @throws PcapException any errors
	 * @since libpcap 0.4
	 */
	public static Pcap0_6 openOffline(String fname) throws PcapException {
		return Pcap0_4.openOffline(Pcap0_6::new, fname);
	}

	/**
	 * Instantiates a new pcap 060.
	 *
	 * @param pcapHandle the pcap handle
	 * @param name       the name
	 */
	protected Pcap0_6(MemoryAddress pcapHandle, String name) {
		super(pcapHandle, name);
	}

}

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
package org.jnetpcap.internal;

import static java.lang.Integer.toUnsignedLong;
import static java.lang.foreign.MemoryLayout.structLayout;
import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;

import org.jnetpcap.windows.PcapStatEx;

/**
 * The PcapStatExRecord.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author mark
 */
public record PcapStatExRecord(
		int size,

		long recv,
		long drop,
		long ifdrop,
		long capt,
		long sent,
		long netdrop,

		long rxPackets,
		long txPackets,
		long rxBytes,
		long txBytes,
		long rxErrors,
		long txErrors,
		long rxDropped,
		long txDropped,
		long multicast,
		long collisions,

		long rxLengthErrors,
		long rxOverErrors,
		long rxCrcErrors,
		long rxFrameErrors,
		long rxFifoErrors,
		long rxMissedErrors,

		long txAbortedErrors,
		long txCarrierErrors,
		long txFifoErrors,
		long txHeartbeatErrors,
		long txWindowErrrors) implements PcapStatEx {

	private static final MemoryLayout LAYOUT = structLayout(
			JAVA_INT.withName("ps_recv"),
			JAVA_INT.withName("ps_drop"),
			JAVA_INT.withName("ps_ifdrop"),
			JAVA_INT.withName("ps_capt"),
			JAVA_INT.withName("ps_sent"),
			JAVA_INT.withName("ps_netdrop"),

			JAVA_LONG.withName("rx_packets"),
			JAVA_LONG.withName("tx_packets"),
			JAVA_LONG.withName("rx_bytes"),
			JAVA_LONG.withName("tx_bytes"),
			JAVA_LONG.withName("rx_errors"),
			JAVA_LONG.withName("tx_errors"),
			JAVA_LONG.withName("rx_dropped"),
			JAVA_LONG.withName("tx_dropped"),
			JAVA_LONG.withName("multicast_cnt"),
			JAVA_LONG.withName("collisions_cnt"),

			JAVA_LONG.withName("rx_length_errors"),
			JAVA_LONG.withName("rx_over_errors"),
			JAVA_LONG.withName("rx_crc_errors"),
			JAVA_LONG.withName("rx_frame_errors"),
			JAVA_LONG.withName("rx_fifo_errors"),
			JAVA_LONG.withName("rx_missed_errors"),

			JAVA_LONG.withName("tx_aborted_errors"),
			JAVA_LONG.withName("tx_carrier_errors"),
			JAVA_LONG.withName("tx_fifo_errors"),
			JAVA_LONG.withName("tx_heartbeat_errors"),
			JAVA_LONG.withName("tx_window_errors")

	);
	
	public static final int PCAP_STAT_EX_LENGTH = (int) LAYOUT.byteSize();

	private static final VarHandle ps_recv = LAYOUT.varHandle(groupElement("ps_recv"));
	private static final VarHandle ps_drop = LAYOUT.varHandle(groupElement("ps_drop"));
	private static final VarHandle ps_ifdrop = LAYOUT.varHandle(groupElement("ps_ifdrop"));
	private static final VarHandle ps_capt = LAYOUT.varHandle(groupElement("ps_ifdrop"));
	private static final VarHandle ps_sent = LAYOUT.varHandle(groupElement("ps_ifdrop"));
	private static final VarHandle ps_netdrop = LAYOUT.varHandle(groupElement("ps_ifdrop"));

	private static final VarHandle rx_packets = LAYOUT.varHandle(groupElement("rx_packets"));
	private static final VarHandle tx_packets = LAYOUT.varHandle(groupElement("tx_packets"));
	private static final VarHandle rx_bytes = LAYOUT.varHandle(groupElement("rx_bytes"));
	private static final VarHandle tx_bytes = LAYOUT.varHandle(groupElement("tx_bytes"));
	private static final VarHandle rx_errors = LAYOUT.varHandle(groupElement("rx_errors"));
	private static final VarHandle tx_errors = LAYOUT.varHandle(groupElement("tx_errors"));
	private static final VarHandle rx_dropped = LAYOUT.varHandle(groupElement("rx_dropped"));
	private static final VarHandle tx_dropped = LAYOUT.varHandle(groupElement("tx_dropped"));
	private static final VarHandle multicast_cnt = LAYOUT.varHandle(groupElement("multicast_cnt"));
	private static final VarHandle collisions_cnt = LAYOUT.varHandle(groupElement("collisions_cnt"));

	private static final VarHandle rx_length_errors = LAYOUT.varHandle(groupElement("rx_length_errors"));
	private static final VarHandle rx_over_errors = LAYOUT.varHandle(groupElement("rx_over_errors"));
	private static final VarHandle rx_crc_errors = LAYOUT.varHandle(groupElement("rx_crc_errors"));
	private static final VarHandle rx_frame_errors = LAYOUT.varHandle(groupElement("rx_frame_errors"));
	private static final VarHandle rx_fifo_errors = LAYOUT.varHandle(groupElement("rx_fifo_errors"));
	private static final VarHandle rx_missed_errors = LAYOUT.varHandle(groupElement("rx_missed_errors"));

	private static final VarHandle tx_aborted_errors = LAYOUT.varHandle(groupElement("tx_aborted_errors"));
	private static final VarHandle tx_carrier_errors = LAYOUT.varHandle(groupElement("tx_carrier_errors"));
	private static final VarHandle tx_fifo_errors = LAYOUT.varHandle(groupElement("tx_fifo_errors"));
	private static final VarHandle tx_heartbeat_errors = LAYOUT.varHandle(groupElement("tx_heartbeat_errors"));
	private static final VarHandle tx_window_errors = LAYOUT.varHandle(groupElement("tx_window_errors"));

	public PcapStatExRecord(int size, MemorySegment mseg) {
		this(
				size,

				toUnsignedLong((int) ps_recv.get(mseg)),
				toUnsignedLong((int) ps_drop.get(mseg)),
				toUnsignedLong((int) ps_ifdrop.get(mseg)),
				toUnsignedLong((int) ps_capt.get(mseg)),
				toUnsignedLong((int) ps_sent.get(mseg)),
				toUnsignedLong((int) ps_netdrop.get(mseg)),

				(long) rx_packets.get(mseg),
				(long) tx_packets.get(mseg),
				(long) rx_bytes.get(mseg),
				(long) tx_bytes.get(mseg),
				(long) rx_errors.get(mseg),
				(long) tx_errors.get(mseg),
				(long) rx_dropped.get(mseg),
				(long) tx_dropped.get(mseg),
				(long) multicast_cnt.get(mseg),
				(long) collisions_cnt.get(mseg),

				(long) rx_length_errors.get(mseg),
				(long) rx_over_errors.get(mseg),
				(long) rx_crc_errors.get(mseg),
				(long) rx_frame_errors.get(mseg),
				(long) rx_fifo_errors.get(mseg),
				(long) rx_missed_errors.get(mseg),

				(long) tx_aborted_errors.get(mseg),
				(long) tx_carrier_errors.get(mseg),
				(long) tx_fifo_errors.get(mseg),
				(long) tx_heartbeat_errors.get(mseg),
				(long) tx_window_errors.get(mseg)

		);
	}
}

/*
 * Copyright 2023 Sly Technologies Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jnetpcap.internal;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.TimeoutException;

import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.constant.PcapCode;
import org.jnetpcap.util.PcapPacketRef;

import static java.lang.foreign.ValueLayout.*;

/**
 * A proxy PcapHandler, which receives packets from native pcap handle and
 * forwards all packets to the sink java PcapHandler.
 */
public class PcapDispatcher implements PacketDispatcher {

	public interface NativeCallbackFunction {

		/**
		 * Native {@code pcap_handler} function, passed as a function pointer to native
		 * libpcap dispatch and loop functions.
		 *
		 * @param user   user opaque data
		 * @param header libpcap header
		 * @param packet packet data
		 * @see {@code typedef void (*pcap_handler)(u_char *user, const struct
		 *      pcap_pkthdr *h, const u_char *bytes);}
		 */
		void nativeCallbackFunc(MemorySegment user, MemorySegment header, MemorySegment packet);

	}

	/**
	 * The Constant pcap_geterr.
	 *
	 * @see {@code char *pcap_geterr(pcap_t *p)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_geterr;

	/**
	 * The Constant pcap_dispatch.
	 *
	 * @see {@code int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback,
	 *      u_char *user)}
	 * @since libpcap 0.4
	 */
	static final PcapForeignDowncall pcap_dispatch;

	/**
	 * The Constant pcap_loop.
	 *
	 * @see {@code int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char
	 *      *user)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_loop;

	/**
	 * This upcall foreign reference is a callback method that is called to java
	 * from pcap_loop and pcap_dispatch calls.
	 * 
	 * @see {@code typedef void (*pcap_handler)(u_char *user, const struct
	 *      pcap_pkthdr *h, const u_char *bytes);}
	 * @since libpcap 0.4
	 */
	static final ForeignUpcall<NativeCallbackFunction> pcap_handler;

	/**
	 * The Constant pcap_next.
	 *
	 * @see {@code const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)}
	 * @since libpcap 0.4
	 */
	private static final PcapForeignDowncall pcap_next;

	/**
	 * The Constant pcap_next_ex.
	 *
	 * @see {@code int pcap_next_ex (pcap_t *p, struct pcap_pkthdr **pkt_header,
	 *      const u_char **pkt_data)}
	 * @since libpcap 0.8
	 */
	private static final PcapForeignDowncall pcap_next_ex;

	static {

		try (var foreign = new PcapForeignInitializer(PcapDispatcher.class)) {

			// @formatter:off
			pcap_geterr      = foreign.downcall("pcap_geterr(A)A"); //$NON-NLS-1$
			pcap_dispatch    = foreign.downcall("pcap_dispatch(AIAA)I");
			pcap_loop        = foreign.downcall("pcap_loop(AIAA)I");
			pcap_next        = foreign.downcall("pcap_next(AA)A");
			pcap_next_ex     = foreign.downcall("pcap_next_ex(AAA)I");
			// @formatter:on

		}
	}
	
	static {

		try (var foreign = new PcapForeignInitializer(NativeCallbackFunction.class)) {

			// @formatter:off
			pcap_handler     = foreign.upcall  ("nativeCallbackFunc(AAA)V", NativeCallbackFunction.class);
			// @formatter:on

		}

	}

	/** The pcap callback stub. */
	private final MemorySegment pcapCallbackStub;

	/** The pcap handle. */
	private final MemorySegment pcapHandle;

	/** The user sink. */
	private NativeCallback userSink;

	/** The arena. */
	protected final Arena arena;

	/** The uncaught exception handler. */
	private UncaughtExceptionHandler uncaughtExceptionHandler;

	/** The uncaught exception. */
	private RuntimeException uncaughtException;

	/** The interrupted. */
	private boolean interrupted = false;

	/** The interrupt on errors. */
	@SuppressWarnings("unused")
	private boolean interruptOnErrors = true;

	/** The break dispatch. */
	private final Runnable breakDispatch;

	/** The abi. */
	private final PcapHeaderABI abi;

	/** The pointer to pointer1. */
	private final MemorySegment POINTER_TO_POINTER1 = Arena.ofAuto().allocate(ADDRESS);

	/** The pointer to pointer2. */
	private final MemorySegment POINTER_TO_POINTER2 = Arena.ofAuto().allocate(ADDRESS);

	/** The pcap header buffer. */
	private final MemorySegment PCAP_HEADER_BUFFER = Arena.ofAuto().allocate(PcapHeaderABI.nativeAbi().headerLength());

	/**
	 * Instantiates a new standard pcap dispatcher.
	 *
	 * @param pcapHandle    the pcap handle
	 * @param abi           the abi
	 * @param breakDispatch the break dispatch
	 */
	public PcapDispatcher(MemorySegment pcapHandle, PcapHeaderABI abi, Runnable breakDispatch) {
		this.pcapHandle = pcapHandle;
		this.abi = abi;
		this.breakDispatch = breakDispatch;
		this.arena = Arena.ofShared();
		this.pcapCallbackStub = pcap_handler.virtualStubPointer(new NativeCallbackFunction() {

			@Override
			public void nativeCallbackFunc(MemorySegment user, MemorySegment header, MemorySegment packet) {
				uncaughtException = null; // Reset any previous unclaimed exceptions

				try (var arena = Arena.ofShared()) {

					header = abi.reinterpretHeader(header, arena);
					packet = abi.reinterpretPacket(header, packet, arena);

					userSink.nativeCallback(user, header, packet);
				} catch (RuntimeException e) {
					onNativeCallbackException(e);
				}
			}

		}, this.arena);
	}

	/**
	 * Capture length.
	 *
	 * @param headerAddress the header address
	 * @return the int
	 * @see org.jnetpcap.internal.PacketDispatcher#captureLength(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int captureLength(MemorySegment headerAddress) {
		return abi.captureLength(headerAddress);
	}

	/**
	 * Close.
	 *
	 * @see java.lang.AutoCloseable#close()
	 */
	@Override
	public void close() {
		if (arena.scope().isAlive())
			arena.close();
	}

	/**
	 * @see org.jnetpcap.internal.PacketDispatcher#dispatchNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int dispatchNative(int count, NativeCallback handler, MemorySegment user) {
		this.userSink = handler;

		return dispatchRaw(
				count,
				pcapCallbackStub,
				user);
	}

	/**
	 * Dispatch raw.
	 *
	 * @param count        the count
	 * @param callbackFunc the callback func
	 * @param userData     the user data
	 * @return the int
	 */
	@Override
	public final int dispatchRaw(int count, MemorySegment callbackFunc, MemorySegment userData) {
		int result = pcap_dispatch.invokeInt(
				pcapHandle,
				count,
				callbackFunc,
				userData);

		if (interrupted)
			handleInterrupt();

		return result;
	}

	/**
	 * Gets the last pcap error string.
	 *
	 * @return the err
	 */
	public final String geterr() {
		return pcap_geterr.invokeString(pcapHandle);
	}

	/**
	 * Dynamic non-pcap utility method to convert libpcap error code to a string, by
	 * various fallback methods with an active pcap handle.
	 *
	 * @param error the code
	 * @return the error string
	 */
	protected String getErrorString(int error) {
		String msg = this.geterr();

		return msg;
	}

	/**
	 * Gets the uncaught exception.
	 *
	 * @return the uncaughtException
	 */
	@Override
	public final RuntimeException getUncaughtException() {
		return uncaughtException;
	}

	/**
	 * Handle interrupt.
	 *
	 * @throws RuntimeException the runtime exception
	 */
	private final void handleInterrupt() throws RuntimeException {
		interrupted = false; // Reset flag

		if (uncaughtException != null) {
			throw uncaughtException;
		}
	}

	/**
	 * Header length.
	 *
	 * @param headerAddress the header address
	 * @return the int
	 * @see org.jnetpcap.internal.PacketDispatcher#headerLength(java.lang.foreign.MemorySegment)
	 */
	@Override
	public int headerLength(MemorySegment headerAddress) {
		return abi.headerLength();
	}

	/**
	 * @see org.jnetpcap.internal.PacketDispatcher#interrupt()
	 */
	@Override
	public final void interrupt() {
		this.breakDispatch.run();
		this.interrupted = true;
	}

	/**
	 * @see org.jnetpcap.internal.PacketDispatcher#loopNative(int,
	 *      org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int loopNative(int count, NativeCallback handler, MemorySegment user) {
		this.userSink = handler;

		return loopRaw(
				count,
				pcapCallbackStub,
				user);
	}

	/**
	 * Loop raw.
	 *
	 * @param count        the count
	 * @param callbackFunc the callback func
	 * @param userData     the user data
	 * @return the int
	 */
	@Override
	public final int loopRaw(int count, MemorySegment callbackFunc, MemorySegment userData) {
		int result = pcap_loop.invokeInt(
				pcapHandle,
				count,
				callbackFunc,
				userData);

		if (interrupted)
			handleInterrupt();

		return result;
	}

	/**
	 * Next.
	 *
	 * @return the pcap packet ref
	 * @throws PcapException the pcap exception
	 * @see org.jnetpcap.internal.PacketDispatcher#next()
	 */
	@Override
	public PcapPacketRef next() throws PcapException {
		MemorySegment hdr = PCAP_HEADER_BUFFER;
		MemorySegment pkt = pcap_next.invokeObj(this::geterr, pcapHandle, hdr);
		if (ForeignUtils.isNullAddress(pkt))
			return null;
		
		hdr = abi.reinterpretHeader(hdr, arena);
		pkt = abi.reinterpretPacket(hdr, pkt, arena);

		return new PcapPacketRef(abi, hdr, pkt);
	}

	/**
	 * Next ex.
	 *
	 * @return the pcap packet ref
	 * @throws PcapException    the pcap exception
	 * @throws TimeoutException the timeout exception
	 * @see org.jnetpcap.internal.PacketDispatcher#nextEx()
	 */
	@Override
	public PcapPacketRef nextEx() throws PcapException, TimeoutException {
		int result = pcap_next_ex.invokeInt(
				this::getErrorString,
				pcapHandle,
				POINTER_TO_POINTER1, // hdr_p
				POINTER_TO_POINTER2); // pkt_p

		if (result == 0)
			throw new TimeoutException();

		else if (result == PcapCode.PCAP_ERROR_BREAK)
			return null;

		MemorySegment hdr = POINTER_TO_POINTER1.get(ADDRESS, 0);
		MemorySegment pkt = POINTER_TO_POINTER2.get(ADDRESS, 0);
		
		hdr = abi.reinterpretHeader(hdr, arena);
		pkt = abi.reinterpretPacket(hdr, pkt, arena);

		return new PcapPacketRef(abi, hdr, pkt);
	}

	/**
	 * Called on a native callback exception within the user handler.
	 *
	 * @param e the exception
	 */
	@Override
	public final void onNativeCallbackException(RuntimeException e) {
		this.uncaughtException = e;

		if (uncaughtExceptionHandler != null) {
			var veto = VetoableExceptionHandler.wrap(uncaughtExceptionHandler);
			if (veto.vetoableException(e)) {
				this.uncaughtException = e;
				interrupt();
			}

		} else {
			this.uncaughtException = e;
			interrupt();
		}
	}

	/**
	 * Pcap header ABI.
	 *
	 * @return the pcap header ABI
	 * @see org.jnetpcap.internal.PacketDispatcher#pcapHeaderABI()
	 */
	@Override
	public PcapHeaderABI pcapHeaderABI() {
		return this.abi;
	}

	/**
	 * @see org.jnetpcap.internal.PacketDispatcher#setUncaughtExceptionHandler(java.lang.Thread.UncaughtExceptionHandler)
	 */
	@Override
	public final void setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		this.uncaughtExceptionHandler = exceptionHandler;
	}
}
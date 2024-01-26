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
import java.lang.foreign.MemorySegment;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import org.jnetpcap.BpFilter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapActivatedException;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHandler.NativeCallback;
import org.jnetpcap.PcapHandler.OfArray;
import org.jnetpcap.PcapHandler.OfMemorySegment;
import org.jnetpcap.PcapStat;
import org.jnetpcap.constant.PcapDirection;
import org.jnetpcap.constant.PcapDlt;
import org.jnetpcap.constant.PcapTStampPrecision;
import org.jnetpcap.constant.PcapTstampType;
import org.jnetpcap.util.PcapPacketRef;

/**
 * The Class NonSealedPcap.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 * @author Mark Bednarczyk
 */
public non-sealed class DelegatePcap<T extends Pcap> extends Pcap {

	private final Pcap pcap;

	/**
	 * Instantiates a new non sealed pcap.
	 *
	 * @param pcapHandle the pcap handle
	 */
	protected DelegatePcap(Pcap pcap) {
		super(pcap);
		this.pcap = pcap;
	}

	/**
	 * @throws PcapActivatedException
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#activate()
	 */
	@Override
	public void activate() throws PcapActivatedException, PcapException {
		pcap.activate();
	}

	/**
	 * 
	 * @see org.jnetpcap.Pcap#breakloop()
	 */
	@Override
	public void breakloop() {
		pcap.breakloop();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#canSetRfmon()
	 */
	@Override
	public boolean canSetRfmon() throws PcapException {
		return pcap.canSetRfmon();
	}

	/**
	 * 
	 * @see org.jnetpcap.Pcap#close()
	 */
	@Override
	public void close() {
		pcap.close();
	}

	/**
	 * @param str
	 * @param optimize
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#compile(java.lang.String, boolean)
	 */
	@Override
	public BpFilter compile(String str, boolean optimize) throws PcapException {
		return pcap.compile(str, optimize);
	}

	/**
	 * @param str
	 * @param optimize
	 * @param netmask
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#compile(java.lang.String, boolean, int)
	 */
	@Override
	public BpFilter compile(String str, boolean optimize, int netmask) throws PcapException {
		return pcap.compile(str, optimize, netmask);
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#datalink()
	 */
	@Override
	public PcapDlt datalink() throws PcapException {
		return pcap.datalink();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dataLinkExt()
	 */
	@Override
	public PcapDlt dataLinkExt() throws PcapException {
		return pcap.dataLinkExt();
	}

	/**
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public int dispatch(int count, NativeCallback handler, MemorySegment user) {
		return pcap.dispatch(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapHandler.OfArray,
	 *      java.lang.Object)
	 */
	@Override
	public <U> int dispatch(int count, OfArray<U> handler, U user) throws PcapException {
		return pcap.dispatch(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dispatch(int,
	 *      org.jnetpcap.PcapHandler.OfMemorySegment, java.lang.Object)
	 */
	@Override
	public <U> int dispatch(int count, OfMemorySegment<U> handler, U user) throws PcapException {
		return pcap.dispatch(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param pcapDumper
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dispatch(int, org.jnetpcap.PcapDumper)
	 */
	@Override
	public <U> int dispatch(int count, PcapDumper pcapDumper) throws PcapException {
		return pcap.dispatch(count, pcapDumper);
	}

	/**
	 * @param fname
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#dumpOpen(java.lang.String)
	 */
	@Override
	public PcapDumper dumpOpen(String fname) throws PcapException {
		return pcap.dumpOpen(fname);
	}

	/**
	 * @param obj
	 * @return
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		return pcap.equals(obj);
	}

	/**
	 * @return
	 * @see org.jnetpcap.Pcap#geterr()
	 */
	@Override
	public String geterr() {
		return pcap.geterr();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#getNonBlock()
	 */
	@Override
	public boolean getNonBlock() throws PcapException {
		return pcap.getNonBlock();
	}

	/**
	 * @return
	 * @see org.jnetpcap.Pcap#getPcapHeaderABI()
	 */
	@Override
	public PcapHeaderABI getPcapHeaderABI() {
		return pcap.getPcapHeaderABI();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#getTstampPrecision()
	 */
	@Override
	public PcapTStampPrecision getTstampPrecision() throws PcapException {
		return pcap.getTstampPrecision();
	}

	/**
	 * @return
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return pcap.hashCode();
	}

	/**
	 * @param packet
	 * @param length
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#inject(java.lang.foreign.MemorySegment, int)
	 */
	@Override
	public int inject(MemorySegment packet, int length) throws PcapException {
		return pcap.inject(packet, length);
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#isSwapped()
	 */
	@Override
	public boolean isSwapped() throws PcapException {
		return pcap.isSwapped();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#listDataLinks()
	 */
	@Override
	public List<PcapDlt> listDataLinks() throws PcapException {
		return pcap.listDataLinks();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#listTstampTypes()
	 */
	@Override
	public List<PcapTstampType> listTstampTypes() throws PcapException {
		return pcap.listTstampTypes();
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.NativeCallback,
	 *      java.lang.foreign.MemorySegment)
	 */
	@Override
	public <U> int loop(int count, NativeCallback handler, MemorySegment user) {
		return pcap.loop(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.OfArray,
	 *      java.lang.Object)
	 */
	@Override
	public <U> int loop(int count, OfArray<U> handler, U user) throws PcapException {
		return pcap.loop(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param handler
	 * @param user
	 * @return
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapHandler.OfMemorySegment,
	 *      java.lang.Object)
	 */
	@Override
	public <U> int loop(int count, OfMemorySegment<U> handler, U user) {
		return pcap.loop(count, handler, user);
	}

	/**
	 * @param <U>
	 * @param count
	 * @param pcapDumper
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#loop(int, org.jnetpcap.PcapDumper)
	 */
	@Override
	public <U> int loop(int count, PcapDumper pcapDumper) throws PcapException {
		return pcap.loop(count, pcapDumper);
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#majorVersion()
	 */
	@Override
	public int majorVersion() throws PcapException {
		return pcap.majorVersion();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#minorVersion()
	 */
	@Override
	public int minorVersion() throws PcapException {
		return pcap.minorVersion();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#next()
	 */
	@Override
	public PcapPacketRef next() throws PcapException {
		return pcap.next();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @throws TimeoutException
	 * @see org.jnetpcap.Pcap#nextEx()
	 */
	@Override
	public PcapPacketRef nextEx() throws PcapException, TimeoutException {
		return pcap.nextEx();
	}

	/**
	 * @param prefix
	 * @return
	 * @see org.jnetpcap.Pcap#perror(java.lang.String)
	 */
	@Override
	public Pcap perror(String prefix) {
		return pcap.perror(prefix);
	}

	/**
	 * @param packet
	 * @param length
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#sendPacket(java.lang.foreign.MemorySegment, int)
	 */
	@Override
	public void sendPacket(MemorySegment packet, int length) throws PcapException {
		pcap.sendPacket(packet, length);
	}

	/**
	 * @param bufferSize
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setBufferSize(int)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setBufferSize(int bufferSize) throws PcapException {
		return (T) pcap.setBufferSize(bufferSize);
	}

	/**
	 * @param dlt
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDatalink(int)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setDatalink(int dlt) throws PcapException {
		return (T) pcap.setDatalink(dlt);
	}

	/**
	 * @param dlt
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDatalink(java.util.Optional)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setDatalink(Optional<PcapDlt> dlt) throws PcapException {
		return (T) pcap.setDatalink(dlt);
	}

	/**
	 * @param dlt
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDatalink(org.jnetpcap.constant.PcapDlt)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setDatalink(PcapDlt dlt) throws PcapException {
		return (T) pcap.setDatalink(dlt);
	}

	/**
	 * @param dir
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDirection(int)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setDirection(int dir) throws PcapException {
		return (T) pcap.setDirection(dir);
	}

	/**
	 * @param dir
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDirection(java.util.Optional)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setDirection(Optional<PcapDirection> dir) throws PcapException {
		return (T) pcap.setDirection(dir);
	}

	/**
	 * @param dir
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setDirection(org.jnetpcap.constant.PcapDirection)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setDirection(PcapDirection dir) throws PcapException {
		return (T) pcap.setDirection(dir);
	}

	/**
	 * @param bpfProgram
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setFilter(org.jnetpcap.BpFilter)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setFilter(BpFilter bpfProgram) throws PcapException {
		return (T) pcap.setFilter(bpfProgram);
	}

	/**
	 * @param bpfProgram
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setFilter(java.util.Optional)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setFilter(Optional<BpFilter> bpfProgram) throws PcapException {
		return (T) pcap.setFilter(bpfProgram);
	}

	/**
	 * @param enable
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setImmediateMode(boolean)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setImmediateMode(boolean enable) throws PcapException {
		return (T) pcap.setImmediateMode(enable);
	}

	/**
	 * @param blockMode
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setNonBlock(boolean)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setNonBlock(boolean blockMode) throws PcapException {
		return (T) pcap.setNonBlock(blockMode);
	}

	/**
	 * @param promiscousMode
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setPromisc(boolean)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setPromisc(boolean promiscousMode) throws PcapException {
		return (T) pcap.setPromisc(promiscousMode);
	}

	/**
	 * @param rfMonitor
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setRfmon(boolean)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setRfmon(boolean rfMonitor) throws PcapException {
		return (T) pcap.setRfmon(rfMonitor);
	}

	/**
	 * @param snaplen
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setSnaplen(int)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setSnaplen(int snaplen) throws PcapException {
		return (T) pcap.setSnaplen(snaplen);
	}

	/**
	 * @param timeoutInMillis
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setTimeout(int)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setTimeout(int timeoutInMillis) throws PcapException {
		return (T) pcap.setTimeout(timeoutInMillis);
	}

	/**
	 * @param precision
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setTstampPrecision(org.jnetpcap.constant.PcapTStampPrecision)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setTstampPrecision(PcapTStampPrecision precision) throws PcapException {
		return (T) pcap.setTstampPrecision(precision);
	}

	/**
	 * @param type
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#setTstampType(org.jnetpcap.constant.PcapTstampType)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setTstampType(PcapTstampType type) throws PcapException {
		return (T) pcap.setTstampType(type);
	}

	/**
	 * @param exceptionHandler
	 * @return
	 * @see org.jnetpcap.Pcap#setUncaughtExceptionHandler(java.util.function.Consumer)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setUncaughtExceptionHandler(Consumer<? super Throwable> exceptionHandler) {
		return (T) pcap.setUncaughtExceptionHandler(exceptionHandler);
	}

	/**
	 * @param exceptionHandler
	 * @return
	 * @see org.jnetpcap.Pcap#setUncaughtExceptionHandler(java.lang.Thread.UncaughtExceptionHandler)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public T setUncaughtExceptionHandler(UncaughtExceptionHandler exceptionHandler) {
		return (T) pcap.setUncaughtExceptionHandler(exceptionHandler);
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#snapshot()
	 */
	@Override
	public int snapshot() throws PcapException {
		return pcap.snapshot();
	}

	/**
	 * @return
	 * @throws PcapException
	 * @see org.jnetpcap.Pcap#stats()
	 */
	@Override
	public PcapStat stats() throws PcapException {
		return pcap.stats();
	}

	/**
	 * @return
	 * @see org.jnetpcap.Pcap#toString()
	 */
	@Override
	public String toString() {
		return pcap.toString();
	}

}

package com.ericsson.eniq.etl.bcd;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.StringTokenizer;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class Fdn {
	private static final long serialVersionUID = -3640770124129258115L;
	String rootMo = null;
	LinkedHashSet<String> _fdn;
	boolean removeRootMoR;
	boolean removeVsData;
	private Logger logger;

	/**
	 * Container for Fully Distinguished Name
	 */
	public Fdn(boolean removeRootMoR, boolean removeVsData,Logger logger) {
		this.removeRootMoR = removeRootMoR;
		this.removeVsData = removeVsData;
		_fdn = new LinkedHashSet<String>();
		this.logger=logger;
	}

	/**
	 * Clears the FDN
	 */
	public void reset() {
		_fdn.clear();
	}

	/**
	 * Handles a new ManagedObject
	 * 
	 * @param mo
	 *            ManagedObject name
	 * @param level
	 *            length of the FDN
	 */
	public void handle(String mo, int level) {
		/*
		 * If the VsData should be removed from the FDN, remove it first
		 */
		if (removeVsData) {
			mo = mo.replaceAll("vsData", "");
		}

		if (_fdn.isEmpty() & rootMo == null) {
			/*
			 * Search for the _R from the RootMO. It has to be removed, so that
			 * the FDN matches the one in statistics
			 */
			Pattern pattern = Pattern.compile(".+_R$");
			Matcher matcher = pattern.matcher(mo);
			/*
			 * Do we have the "_R" in the end? Do we want to remove it?
			 */
			if (matcher.matches() && removeRootMoR) {
				/*
				 * Yes we do, removing it
				 */
				rootMo = mo.substring(0, mo.length() - 2);
			} else {
				/*
				 * We dont, so leave it as it is
				 */
				rootMo = mo;
			}
		} else if (_fdn.isEmpty() & rootMo != null) {
			_fdn.add(mo);
		} else {
			StringTokenizer tk = new StringTokenizer(getFdn(), ",");
			_fdn.clear();
			int count = 0;
			while (tk.hasMoreTokens()) {
				String current = tk.nextToken();
				if (!current.equals(rootMo) && count < level - 1) {
					_fdn.add(current);
					count++;
				}
			}
			_fdn.add(mo);
		}
	}

	/**
	 * Returns the FDN
	 * 
	 * @return String The Fully Distinguished Name
	 */
	public String getFdn() {
		StringBuffer sb = new StringBuffer();
		Iterator<String> it = _fdn.iterator();
		while (it.hasNext()) {
			sb.append(it.next());
			if (it.hasNext()) {
				sb.append(",");
			}
		}
		if (sb.toString().length() == 0) {
			return rootMo;
		} else {
			return rootMo + "," + sb.toString();
		}
	}
	
	
	/**
	 * Returns the FDN data 
	 * 
	 * @param mo
	 * 		  String to be searched in FDN
	 * @return String - FDN data
	 * 
	 */
	public String getFdnData(String searchString)
	{	String fdn=getFdn();
		String fdnData="";
		try(Stream<String> stream=Stream.of(fdn.split(","));) {
			fdnData=stream.filter(s->s.contains(searchString)).collect(Collectors.joining(","));	
		}
		catch(Exception e)
		{
			logger.warning("Exception getting FDN data "+e);
		}
		return fdnData;
		
	}
	
	/**
	 * Returns the Element Parent
	 * 
	 * @return String - Element Parent Name
	 * 
	 */
	public String getElementParent()
	{
		String elementParentInfo="";
		String onlySub=getFdnData("SubNetwork");
		if(!onlySub.isEmpty())
		{
			elementParentInfo=onlySub.substring(onlySub.lastIndexOf('=')+1,onlySub.length());
		}
		return elementParentInfo;
	}
	
	/**
	 * Returns the Element 
	 * 
	 * @return String - Element Name
	 * 
	 */
	public String getElement()
	{
		String element="";
		String onlyMecontext=getFdnData("MeContext");
		String onlyManagedElement=getFdnData("ManagedElement");
		
		if(!onlyMecontext.isEmpty())
		{
			element=onlyMecontext.substring(onlyMecontext.lastIndexOf('=')+1,onlyMecontext.length());
		}
		else if (!onlyManagedElement.isEmpty())
		{
			element=onlyManagedElement.substring(onlyManagedElement.lastIndexOf('=')+1,onlyManagedElement.length());
		}
		
		return element;
	}
	

	/**
	 * Returns the Sender Name
	 * 
	 * @return String The Sender Name Name
	 * 
	 */

	public String getSn()
	{
		String fdn=getFdn();
		String sn;
		String onlyManagedElement=getFdnData("ManagedElement");
		if(!fdn.contains("SubNetwork")&&!fdn.contains("MeContext")) 
		{
			sn=onlyManagedElement;
		}
		else
		{
			if(!onlyManagedElement.isEmpty())
			{
				sn=fdn.substring(0,fdn.indexOf("ManagedElement")).replaceAll(",$", "");
			}
			else
			{
				sn=fdn;
			}
			
		}
		
		return sn;
		
	}
	/**
	 * Returns the Managed Object Identifier 
	 * 
	 * @return String - The Managed Object Identifier Name
	 * 
	 */
	
	public String getMoid()
	{
		String moid="";
		String fdn=getFdn();
		String onlyManagedElement=getFdnData("ManagedElement");
		String onlyMecontext=getFdnData("MeContext");
		if(!onlyManagedElement.isEmpty())
		{
			moid=fdn.substring(fdn.lastIndexOf("ManagedElement"),fdn.length());
		}
		else if(!onlyMecontext.isEmpty())
		{
			moid=onlyMecontext;
		}
		return moid;
	}
}
package com.logiclander.jaasmine.authentication.http;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.List;

import com.google.common.collect.ImmutableList;

abstract class ChallengeHttpAuthorizor implements HttpAuthorizable {
	
	private final ImmutableList<Challenge> challenges;
	
	ChallengeHttpAuthorizor(String realmName) {
		challenges = ImmutableList.of(
				new NegotiateChallenge(),
				new BasicChallenge(realmName)
			);
	}

	@Override
	public List<Challenge> getChallenges() {
		return challenges;
	}

	
	private static class BasicChallenge implements Challenge {

		private static final String BASIC = "Basic";
		
		private final String realmName;
		
		BasicChallenge(String realmName) {
			this.realmName = checkNotNull(realmName);
		}
		
		@Override
		public String getChallengeValue() {
			return String.format("%s realm=\"%s\"", BASIC, realmName);
		}
	}
	
	
	private static class NegotiateChallenge implements Challenge {

		private static final String NEGOTIATE = "Negotiate";
		
		@Override
		public String getChallengeValue() {
			return NEGOTIATE;
		}
		
	}
}

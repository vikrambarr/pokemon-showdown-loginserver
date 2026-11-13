CREATE TABLE `ntbb_discordprofiles` (
	discordid varchar(20) NOT NULL PRIMARY KEY,
	username varchar(32) NOT NULL,
	globalname varchar(64) DEFAULT NULL,
	avatar varchar(64) DEFAULT NULL,
	time BIGINT(20) NOT NULL,
	KEY `username` (`username`),
	KEY `globalname` (`globalname`)
);

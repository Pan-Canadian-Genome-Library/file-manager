import { pool } from '../config/db';
import type { Analysis, AnalysisSamplesMapping, Donor, Sample, Specimen } from '../types';

/**
 * Fetches all samples associated with a specific analysis ID.
 * @param analysisId Analysis ID to fetch samples for
 * @returns
 */
const fetchSamplesSpecimenDonorsForAnalysis = async (analysisId: string): Promise<Sample[]> => {
	const sampleIds = await getSampleIdsForAnalysis(analysisId);

	const samples: Sample[] = [];
	for (const sampleId of sampleIds) {
		const sampleRow = await getSamplesById(sampleId);
		if (!sampleRow) {
			continue;
		}

		const specimenRow = await getSpecimenById(sampleRow.specimen_id);
		if (!specimenRow) {
			continue;
		}

		const specimen: Specimen = {
			specimenId: specimenRow.id,
			specimenType: specimenRow.type,
			submitterSpecimenId: specimenRow.submitter_id,
			tumourNormalDesignation: specimenRow.tumour_normal_designation,
			specimenTissueSource: specimenRow.tissue_source,
		};

		const donorRow = await getDonorById(specimenRow.donor_id);
		if (!donorRow) {
			continue;
		}

		const donor: Donor = {
			donorId: donorRow.id,
			submitterDonorId: donorRow.submitter_id,
			gender: donorRow.gender,
		};

		const sample: Sample = {
			sampleId: sampleRow.id,
			submitterSampleId: sampleRow.submitter_id,
			sampleType: sampleRow.type,
			matchedNormalSubmitterSampleId: sampleRow.matched_normal_submitter_sample_id,
			specimen,
			donor,
		};

		samples.push(sample);
	}
	return samples;
};

/**
 * Retrieves a Donor object from the databse by its ID
 * @param donorId
 * @param specimen
 * @returns
 */
const getDonorById = async (
	donorId: string,
): Promise<{ id: string; study_id: string; submitter_id: string; gender: string } | null> => {
	const result = await pool.query('SELECT * FROM donor WHERE id = $1', [donorId]);
	return result.rows[0];
};

/**
 * Retrieves the samples structure for a list of analyses.
 * @param analysisList An array of Analysis objects to be processed
 * @returns A mapping of analysis_data_id to an array of Sample objects
 */
const getSamplesStructureForAnalyses = async (analysisList: Analysis[]): Promise<AnalysisSamplesMapping> => {
	// entries will be an array of tuples [number, Sample[]]
	const entries: [number, Sample[]][] = await Promise.all(
		analysisList.map(async ({ id, analysis_data_id }) => {
			const samples = await fetchSamplesSpecimenDonorsForAnalysis(id);
			return [analysis_data_id, samples];
		}),
	);

	return Object.fromEntries(entries);
};

/**
 * Retrieves a sample object from the database by its ID
 * @param sampleId
 * @returns
 */
const getSamplesById = async (
	sampleId: string,
): Promise<{
	id: string;
	specimen_id: string;
	submitter_id: string;
	legacy_type: string;
	type: string;
	matched_normal_submitter_sample_id: string;
} | null> => {
	const sampleRes = await pool.query('SELECT * FROM sample WHERE id = $1', [sampleId]);
	return sampleRes.rows[0];
};

/**
 * Get all sample IDs for an analysis
 * @param analysisId
 * @returns
 */
const getSampleIdsForAnalysis = async (analysisId: string): Promise<string[]> => {
	// 'sampleset' table maps the analysis_id with sample_id
	const result = await pool.query('SELECT sample_id FROM sampleset WHERE analysis_id = $1', [analysisId]);
	return result.rows.map((row) => row.sample_id);
};

/**
 * Retrieves a specimen object from the database by its ID
 * @param specimenId
 * @returns
 */
const getSpecimenById = async (
	specimenId: string,
): Promise<{
	id: string;
	donor_id: string;
	submitter_id: string;
	class: string;
	legacy_type: string;
	tissue_source: string;
	tumour_normal_designation: string;
	type: string;
} | null> => {
	const specimenRes = await pool.query('SELECT * FROM specimen WHERE id = $1', [specimenId]);
	return specimenRes.rows[0];
};

export { getSamplesStructureForAnalyses };

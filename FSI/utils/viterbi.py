import torch

from utils import config
from torch.nn.utils.rnn import pack_padded_sequence


def indexed(targets, tagset_size, start_id):
    batch_size, max_len = targets.size()
    for col in range(max_len-1, 0, -1):
        targets[:, col] += (targets[:, col-1] * tagset_size)
    targets[:, 0] += (start_id * tagset_size)
    return targets


def cal_lstm_crf_loss(scores, targets, tag_map, lengths):
    start_id = tag_map.get('<start>')
    end_id = tag_map.get('<end>')
    batch_size = scores.size(0)
    word_pad_len = scores.size(1)

    # Gold score

    targets = targets.unsqueeze(2)
    scores_at_targets = torch.gather(scores.view(batch_size, word_pad_len, -1), 2, targets).squeeze(
        2)  # (batch_size, word_pad_len)

    # Everything is already sorted by lengths
    scores_at_targets = pack_padded_sequence(scores_at_targets, lengths, batch_first=True)[0]
    gold_score = scores_at_targets.sum()

    # All paths' scores

    # Create a tensor to hold accumulated sequence scores at each current tag
    scores_upto_t = torch.zeros(batch_size, len(tag_map)).to(config.device)

    for t in range(max(lengths)):
        batch_size_t = sum([l > t for l in lengths])  # effective batch size (sans pads) at this timestep
        if t == 0:
            scores_upto_t[:batch_size_t] = scores[:batch_size_t, t, start_id, :]  # (batch_size, tagset_size)
        else:
            scores_upto_t[:batch_size_t] = torch.logsumexp(
                scores[:batch_size_t, t, :, :] + scores_upto_t[:batch_size_t].unsqueeze(2),
                dim=1)  # (batch_size, tagset_size)

    # We only need the final accumulated scores at the <end> tag
    all_paths_scores = scores_upto_t[:, end_id].sum()

    viterbi_loss = all_paths_scores - gold_score
    viterbi_loss = viterbi_loss / batch_size

    return viterbi_loss


def decode(crf_scores, lengths, tag_map):
    tagset_size = len(tag_map)
    start_tag = tag_map['<start>']
    end_tag = tag_map['<end>']

    batch_size = crf_scores.size(0)

    # Create a tensor to hold accumulated sequence scores at each current tag
    scores_upto_t = torch.zeros(batch_size, tagset_size).to(config.device)

    # Create a tensor to hold back-pointers
    # i.e., indices of the previous_tag that corresponds to maximum accumulated score at current tag
    # Let pads be the <end> tag index, since that was the last tag in the decoded sequence
    backpointers = torch.ones((batch_size, max(lengths), tagset_size), dtype=torch.long) * end_tag

    for t in range(max(lengths)):
        batch_size_t = sum([l > t for l in lengths])  # effective batch size (sans pads) at this timestep
        if t == 0:
            scores_upto_t[:batch_size_t] = crf_scores[:batch_size_t, t, start_tag, :]  # (batch_size, tagset_size)
            backpointers[:batch_size_t, t, :] = torch.ones((batch_size_t, tagset_size),
                                                           dtype=torch.long) * start_tag
        else:
            # We add scores at current timestep to scores accumulated up to previous timestep, and
            # choose the previous timestep that corresponds to the max. accumulated score for each current timestep
            scores_upto_t[:batch_size_t], backpointers[:batch_size_t, t, :] = torch.max(
                crf_scores[:batch_size_t, t, :, :] + scores_upto_t[:batch_size_t].unsqueeze(2),
                dim=1)  # (batch_size, tagset_size)

    # Decode/trace best path backwards
    decoded = torch.zeros((batch_size, backpointers.size(1)), dtype=torch.long)
    pointer = torch.ones((batch_size, 1),
                         dtype=torch.long) * end_tag  # the pointers at the ends are all <end> tags

    for t in list(reversed(range(backpointers.size(1)))):
        decoded[:, t] = torch.gather(backpointers[:, t, :], 1, pointer).squeeze(1)
        pointer = decoded[:, t].unsqueeze(1)  # (batch_size, 1)

    # Sanity check
    assert torch.equal(decoded[:, 0], torch.ones((batch_size), dtype=torch.long) * start_tag)

    # Remove the <starts> at the beginning, and append with <ends> (to compare to targets, if any)
    decoded = torch.cat([decoded[:, 1:], torch.ones((batch_size, 1), dtype=torch.long) * start_tag],
                        dim=1)

    return decoded
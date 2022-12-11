from torch.utils.data import Dataset


class BDataset(Dataset):

    def __init__(self, bmaps, tmaps, bmap_lengths, addresses):

        self.bmaps = bmaps

        self.tmaps = tmaps
        self.bmap_lengths = bmap_lengths
        self.addresses = addresses

        self.data_size = self.bmaps.size(0)

    def __getitem__(self, i):
        return self.bmaps[i], self.tmaps[i], self.bmap_lengths[i], self.addresses[i]

    def __len__(self):
        return self.data_size


class BIDataset(Dataset):

    def __init__(self, bmaps, imaps_f, imaps_b, imarkers_f, imarkers_b, tmaps, bmap_lengths, imap_lengths, addresses):
        self.bmaps = bmaps
        self.imaps_f = imaps_f
        self.imaps_b = imaps_b
        self.imarkers_f = imarkers_f
        self.imarkers_b = imarkers_b
        self.tmaps = tmaps
        self.bmap_lengths = bmap_lengths
        self.imap_lengths = imap_lengths
        self.addresses = addresses

        self.data_size = self.bmaps.size(0)

    def __getitem__(self, i):
        return self.bmaps[i], self.imaps_f[i], self.imaps_b[i], self.imarkers_f[i], self.imarkers_b[i], self.tmaps[i], \
               self.bmap_lengths[i], self.imap_lengths[i], self.addresses[i]

    def __len__(self):
        return self.data_size